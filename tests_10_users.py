import time, random, socket, os
from contextlib import contextmanager
from colorama import Fore, Style, init as colorama_init
from crypto_utils import load_keys_from_file, sign_message, encrypt_message
from chat_node import ChatNode

colorama_init(autoreset=True)

# ──────────────────────────────────────────
#  Users
# ──────────────────────────────────────────
USERS = [
    ("alice", "pass1", 12001),
    ("bob", "pass2", 12002),
    ("carol", "pass3", 12003),
    ("dave", "pass4", 12004),
    ("eve", "pass5", 12005),
    ("frank", "pass6", 12006),
    ("grace", "pass7", 12007),
    ("heidi", "pass8", 12008),
    ("ivan", "pass9", 12009),
    ("judy", "pass10", 12010),
]

# ──────────────────────────────────────────
#  UDP loss simulation
# ──────────────────────────────────────────
LOSS_PROBABILITY = 0.0
_original_sendto = socket.socket.sendto
_drop_specific_id: str | None = None

def patched_sendto(self, data: bytes, addr):
    if _drop_specific_id and _drop_specific_id.encode() in data:
        return len(data)
    if random.random() < LOSS_PROBABILITY:
        return len(data)
    return _original_sendto(self, data, addr)

@contextmanager
def simulate_loss(prob):
    global LOSS_PROBABILITY
    socket.socket.sendto = patched_sendto
    LOSS_PROBABILITY = prob
    try:
        yield
    finally:
        socket.socket.sendto = _original_sendto
        LOSS_PROBABILITY = 0.0

# ──────────────────────────────────────────
#  Init nodes
# ──────────────────────────────────────────
port_to_username = {p: u for u, _, p in USERS}
def make_node(u, pw, p):
    peers = [("127.0.0.1", other_p) for _, _, other_p in USERS if other_p != p]
    return ChatNode(u, pw, p, peers, port_to_username)

nodes = [make_node(u, pw, p) for u, pw, p in USERS]
by_port = {n.port: n for n in nodes}

# ──────────────────────────────────────────
#  Banner util
# ──────────────────────────────────────────
def banner(txt):
    print(Fore.YELLOW + Style.BRIGHT + f"\n{txt}")

def wait(s, _=""): time.sleep(s)

# ──────────────────────────────────────────
#  TESTS
# ──────────────────────────────────────────
wait(1)

banner("TEST 1 - FIFO broadcast")
by_port[12001].send_broadcast("FIFO 1", type="fifo")
by_port[12001].send_broadcast("FIFO 1", type="fifo")
by_port[12002].send_broadcast("FIFO 2", type="fifo")
wait(3)

with simulate_loss(0.40):
    banner("TEST 2 - Broadcast under 40 % loss")
    by_port[12001].send_broadcast("lossy hello from alice")
    wait(6)

banner("TEST 3 - CAUSAL broadcast")
by_port[12002].send_broadcast("CAUSAL A", type="causal")
by_port[12002].send_broadcast("CAUSAL B", type="causal")
wait(2)
by_port[12001].send_broadcast("CAUSAL C", type="causal")
wait(3)

banner("TEST 4 - Private message (alice ➜ bob)")
by_port[12001].send_private("Hi Bob, secret?", ("127.0.0.1", 12002))
wait(2)

# 5. Private message with invalid signature (crypto fail due to wrong password)
banner("TEST 5 - Private message with WRONG PASSWORD (should fail silently or trigger error)")

try:
    # stop original Alice
    by_port[12001].stop()
    # recreate Alice with wrong password
    bad_alice = ChatNode("alice", "WRONG_PASSWORD", 12001,
                        peers=[("127.0.0.1", p) for _, _, p in USERS if p != 12001],
                        port_to_username=port_to_username)

    # try sending private message
    bad_alice.send_private("This message should fail (wrong password)", ("127.0.0.1", 12002))

    # wait and stop bad node
    wait(2)

except Exception as e:
    print(Fore.RED + Style.BRIGHT + f"Error during TEST 5: {e}")

# ──────────────────────────────────────────
#  Cleanup
# ──────────────────────────────────────────
for n in nodes: n.stop()
print(Fore.GREEN + Style.BRIGHT + "All tests complete!")
