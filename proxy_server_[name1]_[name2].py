import socket
import json

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 6000

# Build your own sample IP blacklist (as required)
IP_BLOCKLIST = {
    "10.0.0.1",
    "192.168.1.50",
    "8.8.8.8",
}

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((PROXY_HOST, PROXY_PORT))
        proxy.listen(5)

        client_conn, client_addr = proxy.accept()
        with client_conn:
            raw = client_conn.recv(4096)
            if not raw:
                return

            text = raw.decode("utf-8", errors="replace")

            # Parse client JSON
            data = json.loads(text)
            server_ip = data["server_ip"]
            server_port = int(data["server_port"])
            message = data["message"]

            # client to server message according to template
            print("------------------------------")
            print("Received from Client:")
            print("------------------------------")
            print("data = {")
            print(f"\"server_ip\": \"{server_ip}\"")
            print(f"\"server_port\": {server_port}")
            print(f"\"message\": \"{message}\"")
            print("}")
            print("------------------------------")

            # this checks the blocklist
            if server_ip in IP_BLOCKLIST:
                blocked_reply = "Blocklist Error"
                print("Sent to Client:")
                print("------------------------------")
                print(f"\"{blocked_reply}\"")
                print("------------------------------")
                client_conn.sendall(blocked_reply.encode("utf-8"))
                return

            # send message to server and get reply
            print("Sent to Server:")
            print("------------------------------")
            print(f"\"{message}\"")
            print("------------------------------")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as to_server:
                to_server.connect((server_ip, server_port))
                to_server.sendall(message.encode("utf-8"))
                server_reply = to_server.recv(4096).decode("utf-8", errors="replace")

            # server to client message according to template
            print("------------------------------")
            print("Received from Server:")
            print("------------------------------")
            print(f"\"{server_reply}\"")
            print("------------------------------")

            print("Sent to Client:")
            print("------------------------------")
            print(f"\"{server_reply}\"")
            print("------------------------------")

            client_conn.sendall(server_reply.encode("utf-8"))

if __name__ == "__main__":
    main()