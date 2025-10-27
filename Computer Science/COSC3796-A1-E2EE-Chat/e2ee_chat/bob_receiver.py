# bob_receiver.py
import socket, json, os, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

HOST, PORT = "127.0.0.1", 5000
MY_NAME = "Bob"

os.makedirs("bob_files", exist_ok=True)
LOG = open("bob_files/messages.json", "a", encoding="utf-8")


def log(entry): LOG.write(json.dumps(entry) + "\n")


def load_keys():
    if os.path.exists("bob_files/private.pem"):
        priv = RSA.import_key(open("bob_files/private.pem", "rb").read())
        pub = RSA.import_key(open("bob_files/public.pem", "rb").read())
        return priv, pub
    key = RSA.generate(2048)
    open("bob_files/private.pem", "wb").write(key.export_key())
    open("bob_files/public.pem", "wb").write(key.publickey().export_key())
    return key, key.publickey()


def send_json(c, o): c.sendall((json.dumps(o) + "\n").encode())


def main():
    priv, pub = load_keys()
    conn = socket.socket(); conn.connect((HOST, PORT))
    send_json(conn, {"type":"register", "name":MY_NAME,
                    "public_key":pub.export_key().decode()})
    print("[Bob] Connected & waiting...")

    sessions = {}
    buf = b""
    while True:
        d = conn.recv(4096)
        if not d: break
        buf += d
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            msg = json.loads(line.decode())
            if msg["type"] == "session_key":
                aes_key = PKCS1_OAEP.new(priv).decrypt(
                    base64.b64decode(msg["cipher_session_key"]))
                sessions[msg["from"]] = aes_key
                print(f"[Bob] Session key received from {msg['from']}")
            elif msg["type"] == "message":
                ct = b64 = msg["ciphertext"]
                print(f"[Bob] Encrypted from {msg['from']}: {ct}")
                log({"enc":ct})
                key = sessions[msg["from"]]
                cipher = AES.new(key, AES.MODE_GCM,
                               nonce=base64.b64decode(msg["nonce"]))
                pt = cipher.decrypt_and_verify(
                    base64.b64decode(msg["ciphertext"]),
                    base64.b64decode(msg["tag"])).decode()
                print(f"[Bob] Decrypted: {pt}")
                log({"plain":pt})


if __name__ == "__main__": main()
