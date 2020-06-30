import socket
import sys
import select
import argparse

# This is a function for broadcasting messages to all other clients
def broadcast_message(s, message):
    for socket in connections:
        if socket != s and socket != server_socket:
            try:
                socket.send(message)
            except:
                socket.close()
                connections.remove(socket)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='port', help='your server\'s port number', required=True)
    args = parser.parse_args()
    # This is a list to track the connections
    connections = []
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # This is a line from piazza
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', int(args.port)))
    server_socket.listen(10)
    connections.append(server_socket)
    try:
        while True:
            # Select from tutorial
            read_list, _, _ = select.select(connections, [], [])
            for s in read_list:
                # New connection comes in
                if s == server_socket:
                    conn, addr = server_socket.accept()
                    connections.append(conn)
                # Message comes from client
                else:
                    data = s.recv(4096)
                    if data:
                        broadcast_message(s, data)
                    else:
                        s.close()
                        connections.remove(s)
                        continue
    # Server closed by pressing ctrl + c
    except KeyboardInterrupt:
        server_socket.close()
        sys.exit()

    except EOFError:
        server_socket.close()
        sys.exit()