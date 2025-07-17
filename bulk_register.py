# bulk_register.py
from register_user import register_user

users = [
    ("alice", "pass1"),
    ("bob", "pass2"),
    ("carol", "pass3"),
    ("dave", "pass4"),
    ("eve", "pass5"),
    ("frank", "pass6"),
    ("grace", "pass7"),
    ("heidi", "pass8"),
    ("ivan", "pass9"),
    ("judy", "pass10")
]

for username, password in users:
    register_user(username, password)
