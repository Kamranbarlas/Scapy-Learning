import socket
import threading
import sys
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ------------------------------------------------------------------------------
# Client RSA Key Generation (Optional)
# ------------------------------------------------------------------------------
# In this design, the client encrypts messages using the server's public key.
# The client does not need to use its own key unless bidirectional encryption is implemented.
CLIENT_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.public_key()

# Global variable to store the server's public key once it is received.
server_public_key = None
server_public_key_lock = threading.Lock()

# ------------------------------------------------------------------------------
# Encryption Function
# ------------------------------------------------------------------------------
def encrypt_message(message: str, public_key) -> bytes:
    """Encrypts the message using RSA OAEP with the provided public key."""
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ------------------------------------------------------------------------------
# Server Message Handler
# ------------------------------------------------------------------------------
def handle_server_messages(sock: socket.socket):
    """
    Continuously listens for messages from the server.
    The first message is expected to be the server's public key in PEM format.
    Subsequent messages are plain text sent by the server.
    """
    global server_public_key
    try:
        # Receive the server's public key (handshake)
        server_public_pem = sock.recv(4096)
        if not server_public_pem:
            print("Failed to receive the server's public key.")
            sock.close()
            sys.exit(1)
        try:
            with server_public_key_lock:
                server_public_key = serialization.load_pem_public_key(server_public_pem)
            print("Received server public key.")
        except Exception as e:
            print(f"Error loading server public key: {e}")
            sock.close()
            sys.exit(1)
    
        # Now continue to receive regular messages (plaintext) from the server.
        while True:
            data = sock.recv(4096)
            if not data:
                print("Server closed the connection.")
                break
            print("Received:", data.decode('utf-8', errors='replace'))
    except ConnectionResetError:
        print("Connection was reset by the server.")
    except Exception as e:
        print("Error receiving data:", e)
    finally:
        sock.close()
        sys.exit()

# ------------------------------------------------------------------------------
# Main Function
# ------------------------------------------------------------------------------
def main():
    global server_public_key
    server_address = ("192.168.200.122", 9997)  # Must match the server's address and port.
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect(server_address)
    except Exception as e:
        print(f"Unable to connect to {server_address}: {e}")
        return

    # Start a daemon thread to listen for server messages (including the public key handshake).
    threading.Thread(target=handle_server_messages, args=(client_socket,), daemon=True).start()

    # Wait until the server's public key has been received.
    while True:
        with server_public_key_lock:
            if server_public_key is not None:
                break
        time.sleep(0.1)

    # Now prompt the user for input and send encrypted messages.
    try:
        while True:
            message = input("You: ")
            if message.lower() in ('exit', 'quit'):
                print("Exiting chat.")
                client_socket.close()
                break

            # Encrypt the message with the server's public key.
            try:
                with server_public_key_lock:
                    encrypted_message = encrypt_message(message, server_public_key)
            except Exception as e:
                print("Encryption error:", e)
                continue

            try:
                client_socket.sendall(encrypted_message)
            except Exception as e:
                print("Failed to send message:", e)
                break
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting.")
        client_socket.close()

if __name__ == "__main__":
    main()
