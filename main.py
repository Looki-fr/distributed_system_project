import argparse
import json
import os
from chat_node import ChatNode

def load_users_from_json(directory="./users"):
    users = []
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            with open(os.path.join(directory, filename), "r") as f:
                user = json.load(f)
                users.append((user["username"], user["password"], user["port"]))
    return users

def main():
    parser = argparse.ArgumentParser(description="Start a ChatNode interactively")
    parser.add_argument("--username", required=True, help="Your username (must match key file)")
    parser.add_argument("--password", required=True, help="Password for your keys")
    parser.add_argument("--port", type=int, required=True, help="Your UDP port")
    args = parser.parse_args()

    USERS = load_users_from_json()

    port_to_username = {p: u for u, _, p in USERS}
    peers = [("127.0.0.1", p) for u, _, p in USERS if p != args.port]

    node = ChatNode(args.username, args.password, args.port, peers, port_to_username)

    try:
        while True:
            cmd = input("> ")
            if cmd.startswith("/q"):
                break
            elif cmd.startswith("/b "):
                parts = cmd.split(maxsplit=2)
                if len(parts) == 2:
                    message = parts[1]
                    node.send_broadcast(message)  # type par défaut = "fifo"
                elif len(parts) == 3:
                    b_type = parts[1].lower()
                    message = parts[2]
                    if b_type not in ("fifo", "causal"):
                        print("Usage: /b [fifo|causal] <message>")
                    else:
                        node.send_broadcast(message, type=b_type)
                else:
                    print("Usage: /b [fifo|causal] <message>")

            elif cmd.startswith("/p "):
                try:
                    parts = cmd.split(maxsplit=2)
                    target_port = int(parts[1])
                    message = parts[2]
                    node.send_private(message, ("127.0.0.1", target_port))
                except:
                    print("Usage: /p <port> <message>")
            else:
                print("Commands:")
                print("  /b [fifo|causal] <message>  broadcast message")
                print("  /p <port> <message>         send private message")
                print("  /q                          quit")
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
        print("Node stopped.")

if __name__ == "__main__":
    main()
