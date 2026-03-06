import socket
import json
import sys

PROXY_IP = "127.0.0.1"
PROXY_PORT = 6000

# These are included in the JSON that goes to the proxy (as required)
SERVER_IP = "8.8.8.8"
SERVER_PORT = 7000

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 client_Hugo_MoralesInfante_and_Xiang_Mao.py <client_message>")
        sys.exit(1)

    client_message = sys.argv[1]

    payload = {
        "server_ip": SERVER_IP,
        "server_port": SERVER_PORT,
        "message": client_message
    }

    print("------------------------------")
    print("Sent to Proxy:")
    print("------------------------------")
    print("data = {")
    print(f"\"server_ip\": \"{payload['server_ip']}\"")
    print(f"\"server_port\": {payload['server_port']}")
    print(f"\"message\": \"{payload['message']}\"")
    print("}")
    print("------------------------------")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PROXY_IP, PROXY_PORT))
        s.sendall(json.dumps(payload).encode("utf-8"))
        reply = s.recv(4096).decode("utf-8", errors="replace")

    print("------------------------------")
    print("Received from Proxy:")
    print("------------------------------")
    print(f"\"{reply}\"")
    print("------------------------------")

if __name__ == "__main__":
    main()