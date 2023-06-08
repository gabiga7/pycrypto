import socket
import json
import threading

def retrieve_ac(public_key):
    print("Connecting to repo_ac to retrieve AC...")
    repo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    repo_socket.connect(('localhost', 6000))  # Connect to repo_ac server
    print(f"Sending public key: {public_key} to repo_ac")

    # Encode public key and get its length
    encoded_public_key = public_key.encode()
    public_key_length = len(encoded_public_key).to_bytes(4, 'big')

    # Send public key length and public key to repo_ac
    repo_socket.sendall(public_key_length + encoded_public_key)

    # Receive the AC
    ac_data = repo_socket.recv(4096).decode()
    print(f"Received AC from repo_ac: {ac_data}")  # Debug: print received AC data

    return ac_data  # return the AC
def handle_client(client_socket):
    print("Handling a new client connection...")

    # Receive the client's public key
    public_key = client_socket.recv(4096).decode()
    print(f"Received public key from client: {public_key}")

    # Retrieve the Attribute Certificate associated with this public key
    print("Retrieving AC associated with the public key...")
    ac_data = retrieve_ac(public_key)

    if ac_data and ac_data.strip() != '':  # Check if ac_data is not empty or None
        # Load AC data from JSON
        ac_dict = json.loads(ac_data)

        # Print AC data for debug
        print("Received Attribute Certificate:")
        print(json.dumps(ac_dict, indent=4))

        # Extract the role from the Attribute Certificate
        role = ac_dict.get('attributes', [{}])[0].get('role', 'unknown')
        print(f"Role extracted from AC: {role}")

        if role == 'manager':
            client_socket.send('Access granted. You can start performing calculations.'.encode())
            print("Access granted to the client. Waiting for calculations...")
            while True:
                # Receive calculation from client
                operation = client_socket.recv(4096).decode()

                # Break the loop and close the connection if client disconnects
                if operation == "":
                    print("Client has disconnected.")
                    break

                # Perform the calculation
                print(f"Performing calculation: {operation}")
                try:
                    result = str(eval(operation))
                    client_socket.send(result.encode())
                    print(f"Calculation result sent to client: {result}")
                except Exception as e:
                    client_socket.send(str(e).encode())
                    print(f"Error during calculation: {e}")

        elif role == 'worker':
            client_socket.send('Access denied.'.encode())
            print("Access denied to the client. Role is 'worker'")
        else:
            client_socket.send('Role not recognized.'.encode())
            print(f"Role not recognized: {role}")
    else:
        client_socket.send('No Attribute Certificate found for this public key.'.encode())
        print("No AC found for this public key.")

    client_socket.close()
    print("Client connection closed.")

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5001))  # Bind to localhost and port 5001
    server_socket.listen(1)

    print('Server listening on localhost:5001')

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print('Accepted connection from:', client_address)
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down the server.")
        server_socket.close()

run_server()
