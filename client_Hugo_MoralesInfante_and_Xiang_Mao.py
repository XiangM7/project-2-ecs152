import socket
import json
import sys

Proxy_IP = "127.0.0.1"
Proxy_Port = 6000


Server_IP = "127.0.0.1"
Server_Port = 7000

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 client_Hugo_MoralesInfante_and_Xiang_Mao.py <client_message>")
        sys.exit(1)

    client_message = sys.argv[1]

    payload = {
        "server_ip": Server_IP,
        "server_port": Server_Port,
        "message": client_message
    }

    print("----------------------------")
    print("Sent to Proxy:")
    print("----------------------------")
    print("data = {")
    print(f"\"server_ip\": \"{payload['server_ip']}\"")
    print(f"\"server_port\": {payload['server_port']}")
    print(f"\"message\": \"{payload['message']}\"")
    print("}")
    print("----------------------------")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((Proxy_IP, Proxy_Port))
        s.sendall(json.dumps(payload).encode("utf-8"))
        reply = s.recv(4096).decode("utf-8", errors="replace")

    print("----------------------------")
    print("Received from Proxy:")
    print("----------------------------")
    print(f"\"{reply}\"")
    print("----------------------------")

if __name__ == "__main__":
    main()