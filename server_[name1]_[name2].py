import socket

HOST = "127.0.0.1"
PORT = 7000

def handle_message(msg: str) -> str:
    # Exactly as spec: Ping<->Pong, else reverse (for any other 4-char string)
    if msg == "Ping":
        return "Pong"
    if msg == "Pong":
        return "Ping"
    return msg[::-1]

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)

        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)
            if not data:
                return

            incoming = data.decode("utf-8", errors="replace")

            print("------------------------------")
            print("Received from Proxy:")
            print("------------------------------")
            print(f"\"{incoming}\"")
            print("------------------------------")

            reply = handle_message(incoming)

            print("Sent to Proxy:")
            print("------------------------------")
            print(f"\"{reply}\"")
            print("------------------------------")

            conn.sendall(reply.encode("utf-8"))

if __name__ == "__main__":
    main()