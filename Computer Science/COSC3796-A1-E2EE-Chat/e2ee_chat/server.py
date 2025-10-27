# server.py
import socket, threading, json

HOST, PORT = "127.0.0.1", 5000
clients, pubkeys = {}, {}


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def handle_client(conn):
    name = None
    buf = b""
    while True:
        data = conn.recv(4096)
        if not data: break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            msg = json.loads(line.decode())
            mtype = msg.get("type")

            if mtype == "register":
                name = msg["name"]
                clients[name] = conn
                pubkeys[name] = msg["public_key"]
                print(f"[SERVER] {name} registered.")
                send_json(conn, {"type":"registered"})

            elif mtype == "get_pubkey":
                target = msg["of"]
                send_json(conn, {"type":"pubkey", "of":target,
                                 "public_key": pubkeys.get(target)})

            elif mtype == "session_key":
                print(f"[SERVER] (session_key) {msg['from']}→{msg['to']}: "
                      f"{msg['cipher_session_key'][:60]}...")
                to = msg["to"]
                if to in clients:
                    send_json(clients[to], msg)

            elif mtype == "message":
                print(f"[SERVER] (ciphertext) {msg['from']}→{msg['to']}: "
                      f"{msg['ciphertext'][:60]}...")
                to = msg["to"]
                if to in clients:
                    send_json(clients[to], msg)

    if name and clients.get(name) is conn:
        del clients[name]
    conn.close()


print(f"[SERVER] Listening on {HOST}:{PORT}")
s = socket.socket()
s.bind((HOST, PORT))
s.listen()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle_client, args=(c,), daemon=True).start()
