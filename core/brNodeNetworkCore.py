import logging
import socket
import os
import threading
import uuid
from core import notrustvars

# Backrooms-net route types and levels

# Control Route - Used internally to consistently talk with other nodes to discuss security, opening routes, ect...
# Test Route - Used internally to test the viability of a route.
# Unencrypted - Can be used if the client on the other end handles it's own encryption/doesn't need it.
#   (Levels) None, Hops(1-12)
# Encrypted - Encrypted with each Node's RSA key. (Onion)
#   (Levels) No-Onion, Hops(1)
#            Low, Hops(2-3), 
#            Medium, Hops(4-5),
#            High, Hops(6-12)
# Highway - If there are many connections going out to one client on the network, a highway (Still a route) can be created.
#           By using a highway, which is a single connection, we can bunch up users together to blend their traffic.
#           This hardens against timing attacks.
#
#           When to use? - When we have more than 5 clients going to the same place.
#           Completely optional. It is up to the client to decide if they want to join the highway.
#           A highway will use the most common level 

#
# On the network
#
#               (No Identification)
# Client A (UUID4) --- HOPS --- Client B (UUID4)



class nodeNetworkController:

    def __init__(self, backlog, bindaddr, port, secureEnclave: notrustvars.enclave, debug: bool) -> None:
        self.backlog = backlog
        self.bindaddr = bindaddr
        self.port = port
        self.secureEnclave = secureEnclave
        self.nodeRunning = False
        self.shutdownSignal = False
        self.debug = debug

        self.connections = []
        self.connAcceptThread = None

    def startNode(self):
        self.connAcceptThread = threading.Thread(name="connAcceptThread", target=self.__nodeLoop__, args=[]).start()

    def __nodeLoop__(self):
        logging.info("Started main node loop for accepting connections...")
        self.nodeRunning = True

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindaddr, self.port))
            soc.listen(self.backlog)
            soc.settimeout(1.0)
        except Exception as e:
            logging.exception("Error occured when creating socket!", exc_info=True)
            self.nodeRunning = False
            return
        
        while self.shutdownSignal is False:
            try:
                socket_connection, address = soc.accept()
                logging.info("Accepting connection from client...")
                #connections.append(socket_connection)
                threading.Thread(target=self.node, args=[socket_connection, address]).start()
                #logging.info(f'Active connections: {len(connections)}')
            except socket.timeout:
                # This is a normal timeout that let's us check for the shutdown signal
                pass
            

        if self.shutdownSignal is True:
            logging.info("Node loop got shutdown signal. Shutting down...")
            #soc.close()
            #logging.info("Closed socket.")
            self.nodeRunning = False
                
    def node(self, connection: socket.socket, address):
        logging.debug("Starting webresponder connection thread...")

        # Append our connection for accurate count
        self.connections.append(connection)

        # Main Responder loop

        while self.shutdownSignal is False:
            try:
                
                msg = connection.recv(1024)

                
                connection.sendall(packet)

            except TimeoutError:
                logging.error("Timeout! Closed connection...")
                break
            except ConnectionResetError:
                logging.exception("Connection force close!", exc_info=True)
                break
            except Exception as e:
                logging.exception(f'Error while handling responder connection!', exc_info=True)
                break


    def remove_connection(self, conn: socket.socket):
        if conn in self.connections:
            conn.close()
            self.connections.remove(conn)
            logging.debug(f'Removed connection. Active connections: {len(self.connections)}')
        else:
            logging.error(f'Attempted to close a connection that does not exist!!! Active connections: {len(self.connections)}')



