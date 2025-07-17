import os, json
from crypto_utils import generate_keys, serialize_keys, hash_password

def register_user(username, password):
    if not os.path.exists("users"):
        os.makedirs("users")

    user_file = f"users/{username}.json"
    if os.path.exists(user_file):
        print("Utilisateur déjà existant.")
        return

    private_key, public_key = generate_keys()
    priv_str, pub_str = serialize_keys(private_key, public_key)
    password_hash = hash_password(password)

    with open(user_file, 'w') as f:
        json.dump({
            "username": username,
            "password": password_hash,
            "private_key": priv_str,
            "public_key": pub_str,
            "port": 12000 + len(os.listdir("users"))  # Simple port assignment
        }, f)

    print(f"Utilisateur {username} enregistré avec succès.")

# Exemple d'utilisation :
# register_user("alice", "motdepasse123")
