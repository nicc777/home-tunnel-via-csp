import socket
import threading
import random
import time
import selectors

from tunnel_server_local_relay import logger
from tunnel_server_local_relay.args import args


RESOURCE_CLIENT_PORT = int(args.resource_client_port)
REMOTE_CLIENT_PORT = int(args.remote_client_port)


def resource_client(client_socket, address):
    logger.info('Resource Client connected')
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            # TODO - Temporary solution !!!! Respond with a random message
            messages = ["Hello from 1234!", "How are you?", "Data received!", "Acknowledged."]
            response = random.choice(messages).encode()
            client_socket.sendall(response)

    except ConnectionResetError:
        logger.error('Remote Client disconnected from {}'.format(address))
    except Exception as e:
        logger.error('Error handling remote client: {}'.format(e))
    finally:
        client_socket.close()


def remote_client(client_socket, address, resource_server_socket):
    logger.info('Remote Client connected')
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            command = data.decode()

            if resource_server_socket:
                try:
                    resource_server_socket.sendall(command.encode())
                    response_from_resource_server = resource_server_socket.recv(1024).decode()
                    client_socket.sendall(response_from_resource_server.encode())
                except (BrokenPipeError, ConnectionResetError):
                    logger.error('Resource server disconnected. Not possible to relay message.')
                    resource_server_socket = None
                    client_socket.sendall('Remote Client disconnected'.encode())
            else:
                client_socket.sendall('No resource client connected'.encode())

    except ConnectionResetError:
        logger.error('Remote Client disconnected')
    except Exception as e:
        logger.error('Error handling remote client: {}'.format(e))
    finally:
        client_socket.close()


def server():
    """Starts the TCP server on two ports."""
    client_1234_socket = None
    try:
        resource_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        resource_server.bind(('0.0.0.0', RESOURCE_CLIENT_PORT))
        resource_server.listen(1)

        remote_client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_client_server.bind(('0.0.0.0', REMOTE_CLIENT_PORT))
        remote_client_server.listen(1)

        logger.info("Server started. Listening on resource server port {} and remote client port {}".format(RESOURCE_CLIENT_PORT, REMOTE_CLIENT_PORT))

        sel = selectors.DefaultSelector()
        sel.register(resource_server, selectors.EVENT_READ, data=resource_server)
        sel.register(remote_client_server, selectors.EVENT_READ, data=remote_client_server)

        while True:
            events = sel.select()
            for key, mask in events:
                server_socket = key.data
                client_socket, address = server_socket.accept()
                if server_socket is resource_server:
                    client_1234_socket = client_socket
                    client_thread = threading.Thread(target=resource_client, args=(client_socket, address))
                    client_thread.start()
                elif server_socket is remote_client_server:
                    client_thread = threading.Thread(target=remote_client, args=(client_socket, address, client_1234_socket))
                    client_thread.start()

    except OSError as e:
        logger.error('Error starting server: {}'.format(e))
    except KeyboardInterrupt:
        logger.error('Server shutting down...')
    finally:
        if resource_server:
            resource_server.close()
        if remote_client_server:
            remote_client_server.close()


def main():
    server_thread = threading.Thread(target=server)
    server_thread.start()
    server_thread.join()
    while True:
        logger.debug('Still alive...')
        time.sleep(60.0)


if __name__ == "__main__":
    main()

