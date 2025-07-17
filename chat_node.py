"""
Fault-tolerant ChatNode.
New features:
• Each outgoing datagram carries a UUID (msg_id).
• Receiver sends back an "ack" packet signed by her private key.
• Sender keeps a retransmission queue and retries up to
  MAX_RETRIES times with RETRANSMIT_INTERVAL seconds spacing.
• Receiver stores recent msg_ids to ignore duplicates when the
  same message is received multiple times (because of retries or
  natural UDP duplication).
• Optional peer-state replication hook (persisted every SYNC_EVERY
  messages) - see _persist_state / _restore_state.
"""

import socket
import threading
import json
import time
import uuid
import os
from collections import deque
from crypto_utils import (
    load_keys_from_file, hash_password, sign_message, verify_signature,
    encrypt_message, decrypt_message
)
from threading import Lock
print_lock = Lock()

RETRANSMIT_INTERVAL = 0.7   # seconds between retries
MAX_RETRIES = 4             # after this we give up
ACK_TIMEOUT = RETRANSMIT_INTERVAL * (MAX_RETRIES + 1)
RECENT_CACHE = 2048         # how many recent msg_ids we remember to drop dups
SYNC_EVERY = 25             # persist local state every N delivered messages
MAX_BUFFER_DURATION = 30  # en secondes

class ChatNode:
    def __init__(self, username, password, port, peers, port_to_username):
        self.username = username
        self.port = port
        self.peers = peers  # list[(ip,port)]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', port))
        self.sock.settimeout(0.3)

        #fifo
        self.fifo_sendSeq = 0
        self.fifo_delivered = {}  # sender -> last_delivered_seq (int)
        self.fifo_buffer = []     # list of (sender, seq, packet)

        # causal
        self.causal_buffer = []  # list of packets waiting for causal delivery

        self.running = True
        self.vector_clock = {}
        self.port_to_username = port_to_username

        # crypto credentials
        self.private_key, self.public_key, stored_hash = load_keys_from_file(username)
        if hash_password(password) != stored_hash:
            raise ValueError("Mot de passe incorrect.")

        self.pending_acks = {}  # msg_id -> (payload_bytes, peer, retries_left, next_due)
        self.recent_ids = deque(maxlen=RECENT_CACHE)

        self.delivered_since_sync = 0
        self._restore_state()

        with print_lock: print(f"[{self.username}] ✅ Fault-tolerant node ready on UDP {port}.", flush=True)

        self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.timer_thread = threading.Thread(target=self._retransmit_loop, daemon=True)
        self.listener_thread.start()
        self.timer_thread.start()
        self._start_periodic_causal_check()


    # -------------------------------- State persistence -------------------------------- #
    def _state_file(self):
        return f".\\states\\{self.username}_state.json"

    def _persist_state(self):
        state = {
            "vector_clock": self.vector_clock,
            "recent_ids": list(self.recent_ids),
        }
        tmp = self._state_file() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(state, fp)
        os.replace(tmp, self._state_file())
        with print_lock: print(f"[{self.username}] 💾 State persisted with vector clock.", flush=True)


    def _restore_state(self):
        try:
            with open(self._state_file(), "r", encoding="utf-8") as fp:
                state = json.load(fp)
            self.vector_clock = state.get("vector_clock", {})
            for mid in state.get("recent_ids", []):
                self.recent_ids.append(mid)
            with print_lock: print(f"[{self.username}] 🔄 Restored vector clock: {self.vector_clock}", flush=True)
        except FileNotFoundError:
            pass

    def _increment_clock(self):
        self.vector_clock[self.username] = self.vector_clock.get(self.username, 0) + 1


    # ------------- Public API ------------- #
    def send_broadcast(self, message, type="fifo"):
        msg_id = str(uuid.uuid4())

        # ✅ D'abord on incrémente
        self._increment_clock()

        # ✅ Ensuite on prend le snapshot (cette version contient "bob": 1)
        vc_snapshot = self.vector_clock.copy()

        signature = sign_message(self.private_key, message)
        payload = {
            "type": "broadcast",
            "broadcast_type": type,
            "id": msg_id,
            "from": self.username,
            "vector_clock": vc_snapshot,
            "sendSeq": self.fifo_sendSeq,
            "message": message,
            "signature": signature,
        }
        self.fifo_sendSeq += 1
        self._send_to_all(json.dumps(payload).encode())

        with print_lock:
            print(f"[{self.username}] 📢 {type.upper()} broadcast → {len(self.peers)} peers | id={msg_id}", flush=True)




    def send_private(self, message: str, target_peer):
        msg_id = str(uuid.uuid4())
        self._increment_clock()
        target_username = self.port_to_username.get(target_peer[1])
        _, target_pub_key, _ = load_keys_from_file(target_username)
        encrypted_msg = encrypt_message(target_pub_key, message)
        signature = sign_message(self.private_key, encrypted_msg)
        payload = {
            "type": "private",
            "id": msg_id,
            "from": self.username,
            "to": target_peer,
            "vector_clock": self.vector_clock.copy(),
            "message": encrypted_msg,
            "signature": signature,
        }
        self._queue_send(json.dumps(payload).encode(), target_peer)
        with print_lock: print(f"[{self.username}] ✉️ private → {target_username}@{target_peer} | id={msg_id} | clock={self.vector_clock}", flush=True)

    def stop(self):
        self.running = False
        self.listener_thread.join()
        self.timer_thread.join()
        self.sock.close()
        self._persist_state()

    # ------------- Internal network helpers ------------- #
    def _queue_send(self, payload: bytes, peer):
        msg_id = json.loads(payload.decode())["id"]
        key = (msg_id, peer)
        self.sock.sendto(payload, peer)
        self.pending_acks[key] = {
            "payload": payload,
            "peer": peer,
            "retries": MAX_RETRIES,
            "next_due": time.time() + RETRANSMIT_INTERVAL,
        }

    def _send_to_all(self, payload: bytes):
        for peer in self.peers:
            self._queue_send(payload, peer)

    def _fifo_buffer_packet(self, sender, seq, packet):
        self.fifo_buffer.append((sender, seq, packet))

    def _fifo_try_deliver(self):
        delivered_any = True
        while delivered_any:
            delivered_any = False
            for entry in list(self.fifo_buffer):
                sender, seq, packet = entry
                expected = self.fifo_delivered.get(sender, 0)
                if seq == expected:
                    # message prêt à être livré
                    msg_content = packet.get("message", "")
                    with print_lock: print(f"[{self.username}] 📥 FIFO BROADCAST {sender} | seq={seq} | {msg_content}", flush=True)
                    self.fifo_delivered[sender] = expected + 1
                    self.fifo_buffer.remove(entry)
                    delivered_any = True
                    break  # restart from beginning

    def _start_periodic_causal_check(self):
        def loop():
            while True:
                time.sleep(0.5)
                try:
                    self._causal_try_deliver()
                except:
                    pass

        threading.Thread(target=loop, daemon=True).start()

    def _causal_try_deliver(self):
        delivered_any = True
        now = time.time()
        while delivered_any:
            delivered_any = False
            for packet in list(self.causal_buffer):
                try:
                    ts = packet.get("_ts", None)
                    if ts and now - ts > MAX_BUFFER_DURATION:
                        self.causal_buffer.remove(packet)
                        with print_lock:
                            print(f"[{self.username}] 🧹 dropped stale msg from {packet['from']}", flush=True)
                        continue

                    sender = packet["from"]
                    recv_vector = packet["vector_clock"]

                    causal_ok = True
                    blocking_reasons = []

                    for u, val in recv_vector.items():
                        local_val = self.vector_clock.get(u, 0)
                        if u == sender:
                            if val != local_val + 1:
                                causal_ok = False
                                blocking_reasons.append(f"{u}: need {local_val + 1}, got {val}")
                        else:
                            if val > local_val:
                                causal_ok = False
                                blocking_reasons.append(f"{u}: need ≤ {local_val}, got {val}")

                    if causal_ok:
                        msg_content = packet["message"]
                        with print_lock:
                            print(f"[{self.username}] 📥 CAUSAL BROADCAST {sender} | VC={recv_vector} | {msg_content}", flush=True)

                        for u, val in recv_vector.items():
                            current_val = self.vector_clock.get(u, 0)
                            self.vector_clock[u] = max(current_val, val)

                        try:
                            self.causal_buffer.remove(packet)
                        except ValueError:
                            pass
                        delivered_any = True
                    else:
                        with print_lock:
                            print(f"[{self.username}] ⏸ blocked causal msg from {sender} | VC={recv_vector} | local={self.vector_clock} | reasons={blocking_reasons}", flush=True)

                except Exception as e:
                    with print_lock:
                        print(f"[{self.username}] ❌ _error in causal delivery: {e}", flush=True)

               

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                packet = json.loads(data.decode())
                p_type = packet.get("type", "?")

                if p_type == "ack":
                    self._handle_ack(packet, addr)
                    continue

                msg_id = packet.get("id")
                if msg_id in self.recent_ids:
                    # Duplicate - acknowledge again to be polite, then ignore
                    self._send_ack(msg_id, addr)
                    continue
                self.recent_ids.append(msg_id)

                sender = packet.get("from", "???")
                recv_vector = packet.get("vector_clock", {})

                # Merge received vector clock into local one
                if not (p_type == "broadcast" and packet.get("broadcast_type", "fifo") == "causal"):
                    for user, received_ts in recv_vector.items():
                        current_ts = self.vector_clock.get(user, 0)
                        self.vector_clock[user] = max(current_ts, received_ts)

                signature = packet.get("signature", "")
                msg_content = packet.get("message", "")

                # Verify signature
                try:
                    sender_pub = load_keys_from_file(sender)[1]
                    verified = verify_signature(sender_pub, msg_content, signature)
                except Exception:
                    verified = False

                if not verified:
                    with print_lock: print(f"[{self.username}] ❌ DROP (bad sig) from {sender}", flush=True)
                    continue

                # send ack first (even if decryption fails)
                self._send_ack(msg_id, addr)

                if p_type == "private":
                    self._increment_clock()  # Increment our own clock for this message
                    try:
                        clear = decrypt_message(self.private_key, msg_content)
                    except Exception:
                        clear = "[ERREUR DE DÉCHIFFREMENT]"
                    with print_lock: print(f"[{self.username}] 📥 PRIVATE {sender} | 🕒 {recv_vector} | decrypted={clear} | crypt={msg_content}", flush=True)
                elif p_type == "broadcast":
                    try:
                        seq = packet.get("sendSeq", -1)
                        b_type = packet.get("broadcast_type", "fifo")
                        if b_type == "fifo":
                            self._fifo_buffer_packet(sender, seq, packet)
                            self._fifo_try_deliver()
                        elif b_type == "causal":
                            packet["_ts"] = time.time()
                            self.causal_buffer.append(packet)
                            try:
                                self._causal_try_deliver()
                            except Exception as e:
                                with print_lock: print(f"[{self.username}] ❌ _causal_try_deliver crash: {e}", flush=True)

                        else:
                            with print_lock: print(f"[{self.username}] ❓ Unknown broadcast_type: {b_type}", flush=True)
                    except Exception as e:
                        with print_lock: print(f"[{self.username}] ❌ Error handling broadcast: {e}", flush=True)



                self.delivered_since_sync += 1
                if self.delivered_since_sync >= SYNC_EVERY:
                    self._persist_state()
                    self.delivered_since_sync = 0

            except socket.timeout:
                continue
            except Exception as e:
                with print_lock: print(f"[{self.username}] ⚠️ recv error: {e}", flush=True)

    def _send_ack(self, msg_id: str, peer):
        ack = {
            "type": "ack",
            "id": msg_id,
            "from": self.username,
        }
        self.sock.sendto(json.dumps(ack).encode(), peer)
        # with print_lock: print(f"[{self.username}] 🔁 ack → {msg_id[:8]} → {peer}")


    def _handle_ack(self, packet, addr):
        acked_id = packet.get("id")
        key = (acked_id, addr)
        if key in self.pending_acks:
            del self.pending_acks[key]
            # with print_lock: print(f"[{self.username}] ✅ ack for {acked_id[:8]} from {addr}")

    def _retransmit_loop(self):
        while self.running:
            now = time.time()
            for key, entry in list(self.pending_acks.items()):
                msg_id, peer = key
                if now >= entry["next_due"]:
                    if entry["retries"] <= 0:
                        with print_lock: print(f"[{self.username}] 🚫 give-up {msg_id[:8]} → {peer}", flush=True)
                        del self.pending_acks[key]
                        continue

                    # resend
                    self.sock.sendto(entry["payload"], peer)
                    entry["retries"] -= 1
                    entry["next_due"] = now + RETRANSMIT_INTERVAL
                    with print_lock: print(
                        f"[{self.username}] 🔁 retry {msg_id[:8]} → "
                        f"{peer} ({entry['retries']} left)", flush=True
                    )
            time.sleep(0.1)
