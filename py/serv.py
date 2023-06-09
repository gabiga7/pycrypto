import json
import random
import socket
import threading

# Color codes for messages
COLORS = {}

def assign_color(server_name):
    if server_name not in COLORS:
        # Generate a random color code
        while True:
            color_code = '\033[{}m'.format(random.randint(91, 96))
            if color_code not in COLORS.values():
                break
        COLORS[server_name] = color_code

def handle_client(client_socket, access_rules, server_name):
    assign_color(server_name)
    color_code = COLORS[server_name]

    try:
        while True:
            # Receive data from the client
            data = client_socket.recv(1024).decode()
            print(color_code + 'Received data from client for server "{}":'.format(server_name), data, '\033[0m')

            # Check if client wants to exit
            if data.lower() == 'exit':
                break

            # Process the data or perform any application logic

            # Send a response back to the client
            response = 'Hello, client!'
            client_socket.sendall(response.encode())

    except ConnectionAbortedError:
        print(color_code + 'Client connection closed abruptly', '\033[0m')

    finally:
        client_socket.close()

def start_server(server_config):
    # Extract server configuration
    name = server_config['name']
    ip = server_config['ip']
    port = int(server_config['port'])
    access_rules = server_config['access_rules']

    assign_color(name)
    color_code = COLORS[name]

    print(color_code + 'Server "{}" listening on {}:{}'.format(name, ip, port), '\033[0m')

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the host and port
    server_socket.bind((ip, port))

    # Listen for incoming connections
    server_socket.listen()

    while True:
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        print(color_code + 'Connected to client:', client_address, '\033[0m')

        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket, access_rules, name))
        client_thread.start()

def main():
    # Read config.json
    with open('config.json') as config_file:
        config = json.load(config_file)

    # Start servers concurrently based on the configurations
    servers = config['servers']
    threads = []
    for server_config in servers:
        server_thread = threading.Thread(target=start_server, args=(server_config,))
        threads.append(server_thread)
        server_thread.start()

    # Wait for all server threads to finish
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
