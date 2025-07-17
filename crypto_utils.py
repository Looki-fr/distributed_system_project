from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64, os, json, hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes.decode(), pub_bytes.decode()

def sign_message(private_key, message: str):
    return base64.b64encode(private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )).decode()

def verify_signature(public_key, message: str, signature: str) -> bool:
    try:
        public_key.verify(
            base64.b64decode(signature.encode()),
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

def load_keys_from_file(username: str):
    with open(f'users/{username}.json', 'r') as f:
        data = json.load(f)
    priv = serialization.load_pem_private_key(data['private_key'].encode(), password=None)
    pub = serialization.load_pem_public_key(data['public_key'].encode())
    return priv, pub, data['password']

def encrypt_message(public_key, message: str) -> str:
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_message(private_key, encrypted_b64: str) -> str:
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_b64.encode()),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        print(f"❌ ERREUR DE DÉCHIFFREMENT : {e}")
        raise

