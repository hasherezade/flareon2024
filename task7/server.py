import socket
import sys
import argparse
import struct

connection = None

def main():
    parser = argparse.ArgumentParser(description="Mini server")
    parser.add_argument('--port', dest="port", default="31337", help="Port to connect")

    args = parser.parse_args()
    my_port = int(args.port)
    print('[+] Opening the port: ' + str(my_port))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('', my_port)
        s.bind(server_address)
        s.listen(1)
        while True:
            # Wait for a connection
            print('waiting for a connection')
            client_connection, client_address = s.accept()
            connection = client_connection
            try:
                print('connection from', client_address)
                while True: 
                    data = client_connection.recv(96)
                    print("data1:")
                    print(data)
                    buffer2 = bytes.fromhex('a0d2eba817e38b03cd063227bd32e353880818893ab02378d7db3c71c5c725c6bba0934b5d5e2d3ca6fa89ffbb374c3196a35eaf2a5e0b430021de361aa58f8015981ffd0d9824b50af23b5ccf16fa4e323483602d0754534d2e7a8aaf8174dcf272d54c31860f')
                    client_connection.sendall(buffer2)
                client_connection.close()
                s.close()
                return
            except socket.error:
                print("Could not connect to the socket. ")
            finally:
                client_connection.close()
                s.close()
                return
    finally:
        s.close()

        
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
        
        
