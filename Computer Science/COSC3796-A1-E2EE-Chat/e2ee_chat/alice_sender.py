# alice_sender.py
import socket, json, base64, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST, PORT = "127.0.0.1", 5000
MY_NAME, PEER = "Alice", "Bob"

os.makedirs("alice_files", exist_ok=True)
LOG = open("alice_files/messages.json", "a", encoding="utf-8")


def log(e): LOG.write(json.dumps(e) + "\n")


def load_keys():
    if os.path.exists("alice_files/private.pem"):
        priv = RSA.import_key(open("alice_files/private.pem", "rb").read())
        pub = RSA.import_key(open("alice_files/public.pem", "rb").read())
        return priv, pub
    key = RSA.generate(2048)
    open("alice_files/private.pem", "wb").write(key.export_key())
    open("alice_files/public.pem", "wb").write(key.publickey().export_key())
    return key, key.publickey()


def send_json(c, o): c.sendall((json.dumps(o) + "\n").encode())


def recv_json(c):
    buf = b""
    while True:
        d = c.recv(4096)
        if not d: raise SystemExit("server closed")
        buf += d
        if b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            return json.loads(line.decode())


def main():
    priv, pub = load_keys()
    conn = socket.socket(); conn.connect((HOST, PORT))
    send_json(conn, {"type":"register", "name":MY_NAME,
                    "public_key":pub.export_key().decode()})
    recv_json(conn)  # ack
    send_json(conn, {"type":"get_pubkey", "of":PEER})
    peer_pub = RSA.import_key(recv_json(conn)["public_key"])

    aes_key = get_random_bytes(32)
    enc_key = PKCS1_OAEP.new(peer_pub).encrypt(aes_key)
    send_json(conn, {"type":"session_key", "from":MY_NAME, "to":PEER,
                    "cipher_session_key":base64.b64encode(enc_key).decode()})
    print("[Alice] Session key sent. Type message & Enter (blank to quit).")

    while True:
        txt = input("> ").strip()
        if not txt: break
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(txt.encode())
        msg = {"type":"message", "from":MY_NAME, "to":PEER,
             "ciphertext":base64.b64encode(ct).decode(),
             "nonce":base64.b64encode(cipher.nonce).decode(),
             "tag":base64.b64encode(tag).decode()}
        send_json(conn, msg)
        print(f"[Alice] Sent (ciphertext): {msg['ciphertext']}")
        log({"plain":txt, "enc":msg["ciphertext"]})


if __name__ == "__main__": main()
