"""
This code is to explore a concept of TCP tunneling.

Original code created with Google Gemini AI. Modifications (if any) will be in
a file called "scripts/test_relay_concept_1_modified.py"

Prompt:

    In python3, how can I create a simple TCP server that listens on two 
    different TCP ports (1234 and 4567 respectively) in two separate threads
    with different handlers for each port? I also need a python client to
    connect to port 1234, but it must only listen for data and respond with a
    random message. Then I also want another Python client connecting to port
    4567 which will send commands. The commands received on port 4567 must be
    send to the client connected to port 1234 and the response from that client
    must be relayed back to the client that originally send the message on port
    4567. 
"""

import socket
import threading
import random
import time

def handle_client_1234(client_socket, address):
    """Handles clients connected to port 1234 (data receiver)."""
    print(f"Client connected to 1234: {address}")
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"Received data on 1234: {data.decode()}")
            # Respond with a random message
            messages = ["Hello from 1234!", "How are you?", "Data received!", "Acknowledged."]
            response = random.choice(messages).encode()
            client_socket.sendall(response)

    except ConnectionResetError:
        print(f"Client disconnected from 1234: {address}")
    except Exception as e:
        print(f"Error handling client 1234: {e}")
    finally:
        client_socket.close()

def handle_client_4567(client_socket, address, client_1234_socket):
    """Handles clients connected to port 4567 (command sender)."""
    print(f"Client connected to 4567: {address}")
    try:
        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break
            print(f"Received command on 4567: {command}")

            if client_1234_socket: #check if there is a client connected on port 1234
                try:
                    client_1234_socket.sendall(command.encode())
                    response_1234 = client_1234_socket.recv(1024).decode()
                    client_socket.sendall(response_1234.encode())
                    print(f"Relayed response to client 4567: {response_1234}")
                except (BrokenPipeError, ConnectionResetError):
                    print("Client 1234 disconnected. Can't relay message.")
                    client_1234_socket = None #remove the client to avoid errors
                    client_socket.sendall("Client 1234 disconnected".encode())
            else:
                client_socket.sendall("No client connected on port 1234".encode())


    except ConnectionResetError:
        print(f"Client disconnected from 4567: {address}")
    except Exception as e:
        print(f"Error handling client 4567: {e}")
    finally:
        client_socket.close()

def server():
    """Starts the TCP server on two ports."""
    client_1234_socket = None # Variable to store the socket of the client connected on port 1234
    try:
        server_1234 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_1234.bind(('localhost', 1234))
        server_1234.listen(1)

        server_4567 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_4567.bind(('localhost', 4567))
        server_4567.listen(1)

        print("Server started. Listening on ports 1234 and 4567...")

        while True:
            readable, writable, exceptional = socket.select([server_1234, server_4567], [], [])
            for s in readable:
                client_socket, address = s.accept()
                if s is server_1234:
                    client_1234_socket = client_socket
                    client_thread = threading.Thread(target=handle_client_1234, args=(client_socket, address))
                    client_thread.start()
                elif s is server_4567:
                    client_thread = threading.Thread(target=handle_client_4567, args=(client_socket, address, client_1234_socket))
                    client_thread.start()

    except OSError as e:
        print(f"Error starting server: {e}")
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_1234.close()
        server_4567.close()

def client_1234():
    """Simple client that connects to port 1234 and just receives data and responds."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('localhost', 1234))
        while True:
            data = client.recv(1024)
            if not data:
                break
            print(f"Received from server 1234: {data.decode()}")
            messages = ["Hello from Client 1234!", "Client 1234 is here!", "Message Received!"]
            response = random.choice(messages).encode()
            client.sendall(response)
            time.sleep(1) # wait 1 second before sending another message
    except ConnectionRefusedError:
        print("Server 1234 is not running.")
    except Exception as e:
        print(f"Client 1234 error: {e}")
    finally:
        client.close()

def client_4567():
    """Client that sends commands to port 4567."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('localhost', 4567))
        while True:
            command = input("Enter command (or 'exit' to quit): ")
            if command.lower() == 'exit':
                break
            client.sendall(command.encode())
            response = client.recv(1024).decode()
            print(f"Response from server 4567: {response}")
    except ConnectionRefusedError:
        print("Server 4567 is not running.")
    except Exception as e:
        print(f"Client 4567 error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    server_thread = threading.Thread(target=server)
    server_thread.start()

    time.sleep(1) # wait for the server to start

    client_1234_thread = threading.Thread(target=client_1234)
    client_1234_thread.start()
    
    time.sleep(1) # wait for the first client to connect

    client_4567_thread = threading.Thread(target=client_4567)
    client_4567_thread.start()

    server_thread.join()
    client_1234_thread.join()
    client_4567_thread.join()