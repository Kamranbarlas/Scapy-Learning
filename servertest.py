


import socket
import threading
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ------------------------------------------------------------------------------
# RSA Key Generation (Server Side)
# ------------------------------------------------------------------------------
SERVER_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()

# Serialize the server's public key in PEM format (this will be sent to each client)
SERVER_PUBLIC_PEM = SERVER_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Global list of connected client sockets and a lock for safe multi-thread access
clients = []
clients_lock = threading.Lock()

# ------------------------------------------------------------------------------
# Decryption Function
# ------------------------------------------------------------------------------
def decrypt_message(ciphertext: bytes, private_key) -> str:
    """
    Decrypts ciphertext using RSA OAEP with the provided private key.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

# ------------------------------------------------------------------------------
# Broadcast Function
# ------------------------------------------------------------------------------
def broadcast_message(message: str, sender_socket: socket.socket = None):
    """
    Sends a plaintext message to all connected clients. Optionally, do not echo
    the message to the sender.
    """
    with clients_lock:
        for client in clients:
            if client is not sender_socket:
                try:
                    client.sendall(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error broadcasting to a client: {e}")

# ------------------------------------------------------------------------------
# Client Handler
# ------------------------------------------------------------------------------
def handle_client(client_socket: socket.socket, client_address):
    """
    Handles incoming messages from a connected client.
    First, sends the server's public key (PEM) as handshake.
    Then, receives encrypted messages, decrypts them, prints them,
    and broadcasts the plaintext to all other clients.
    """
    print(f"Client {client_address} connected.")

    # Send the server's public key so the client can encrypt its messages.
    try:
        client_socket.sendall(SERVER_PUBLIC_PEM)
    except Exception as e:
        print(f"Failed to send public key to client {client_address}: {e}")
        client_socket.close()
        return

    try:
        while True:
            # Read the next encrypted message from the client.
            data = client_socket.recv(4096)
            if not data:
                # Connection closed by the client.
                print(f"Client {client_address} disconnected.")
                break

            try:
                decrypted_message = decrypt_message(data, SERVER_PRIVATE_KEY)
                print(f"[{client_address}] {decrypted_message}")
                # Optionally, broadcast this message to all other clients.
                broadcast_message(f"[{client_address}] {decrypted_message}", sender_socket=client_socket)
            except Exception as e:
                print(f"Failed to decrypt message from {client_address}: {e}")
    except ConnectionResetError:
        print(f"Connection reset by client {client_address}.")
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()

# ------------------------------------------------------------------------------
# Server Input Handler (Optional)
# ------------------------------------------------------------------------------
def server_input_handler():
    """
    Allows the server operator to type messages that will be broadcast to all clients.
    These messages are sent as plaintext.
    """
    while True:
        try:
            message = input()
            if message.lower() in ('exit', 'quit'):
                print("Server shutdown initiated.")
                # Close all client sockets.
                with clients_lock:
                    for client in clients:
                        client.close()
                sys.exit(0)
            broadcast_message(f"[SERVER] {message}")
        except Exception as e:
            print(f"Error in server input: {e}")
            break

# ------------------------------------------------------------------------------
# Main Function to Run the Server
# ------------------------------------------------------------------------------
def main():
    server_address = ("192.168.200.122",9997 )
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server_socket.bind(server_address)
        server_socket.listen(5)
        print(f"Server is listening on {server_address[0]}:{server_address[1]} ...")
    except Exception as e:
        print(f"Unable to start the server on {server_address}: {e}")
        sys.exit(1)
        
    # Start a separate thread to read input from the server operator.
    threading.Thread(target=server_input_handler, daemon=True).start()
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            with clients_lock:
                clients.append(client_socket)
            # Start a new thread for the connected client.
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, client_address), daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down (keyboard interrupt).")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()