# Fault-Tolerant ChatNode

This repository contains a fault-tolerant UDP-based chat system using `ChatNode`. It supports both **automated tests** to validate failure scenarios, and a **real interactive client** to allow humans to connect from multiple consoles.

## Features

* 10 simulated users
* Color-coded output (using `colorama`)
* Non-blocking timers with a while-loop instead of `sleep()`
* Retransmission queue and ACK system to tolerate UDP loss
* Duplicate `msg_id` detection to ignore repeated packets
* Signature verification for message integrity
* Optional peer-state persistence
* Fault injection (packet loss, duplicate IDs, bad signatures, wrong-key encryption)
* Interactive command-line client to send real messages

---

## Test Scenarios

The integration tests verify the reliability, ordering guarantees, and security of the chat system:

1. **FIFO Broadcast**  
   Alice and Bob send FIFO messages to the group. Ensures that messages are received in the correct order per sender.

2. **Broadcast under 40% Packet Loss**  
   Alice broadcasts a message while simulating 40% UDP packet loss. Verifies message delivery resilience despite network unreliability.

3. **Causal Broadcast**  
   Bob sends two causally linked messages, then Alice sends a dependent one. Validates that messages are delivered respecting causal dependencies.

4. **Private Messaging (Valid Signature)**  
   Alice sends a private, encrypted message to Bob. Verifies correct encryption and signature using asymmetric cryptography.

5. **Private Messaging with Wrong Password**  
   A new "Alice" instance with the wrong password tries to send a private message. Ensures that signature verification fails gracefully (i.e., message is rejected or ignored without crash).

6. **Shutdown and Cleanup**  
   All nodes are gracefully stopped at the end of the tests.


---

## File Structure

* `register_user.py`
  Register a single user interactively.

* `bulk_register.py`
  Bulk-register the 10 default users with keys and passwords.

* `chat_node.py`
  Implementation of the `ChatNode` class with fault tolerance.

* `crypto_utils.py`
  Cryptographic helpers for loading keys, signing messages, and encryption/decryption.

* `tests_10_users.py`
  Runs the five integration tests on 10 simulated users.

* `main.py`
  An interactive command-line client to connect as a real user.

---

## Installation

First, install the dependencies:

```bash
pip install cryptography colorama
```

---

## Running the Tests

To run the automated test scenarios:

```bash
python tests_10_users.py
```

---

## Using the Interactive Main Client

You can also launch multiple ChatNodes manually, each in its own terminal window:

```bash
python main.py --username alice --password pass1 --port 12001
python main.py --username bob --password pass2 --port 12002
python main.py --username carol --password pass3 --port 12003
```

**Commands inside the main client:**

* `/b <message>`
  Send a broadcast message to all known peers.

* `/p <port> <message>`
  Send a private message to a specific peer by UDP port.

* `/q`
  Quit the chat node gracefully.

**Example usage:**

```text
> /b Hello to all
> /p 12001 Hey Bob, this is Alice
> /q
```

Make sure you have the required key files (e.g. `alice.priv`, `alice.pub`, etc.) present in your working directory. If they do not exist, you can generate them using `bulk_register.py`.

---

## Notes

* All communication is on `127.0.0.1` using UDP ports 12000-12009.
* Designed for local machine testing only.
* State is persisted under the `.\\states` directory.

---

Happy testing and enjoy building robust fault-tolerant chat systems!
