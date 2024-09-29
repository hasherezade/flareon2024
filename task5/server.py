import socket
import sys
import argparse
import struct

connection = None

def main():
    parser = argparse.ArgumentParser(description="Mini server")
    parser.add_argument('--port', dest="port", default="1337", help="Port to connect")
    parser.add_argument('--inp', dest="inp", default="file.dat", help="Input File")
    parser.add_argument('--out', dest="out", default="out_file.dat", help="Output File")
    args = parser.parse_args()
    my_port = int(args.port)
    inp_filename = args.inp
    out_filename = args.out
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
                # Receive the message and send "Hello" back to the client
                client_connection.sendall(b'01234567890123456789012345678945')
                print(b'01234567890123456789012345678945')
                client_connection.sendall(b'123456789012')
                byte_buffer = bytes(struct.pack('@I', len(inp_filename)))
                client_connection.sendall(byte_buffer)
                byte_buffer = bytearray(inp_filename, 'utf-8')
                client_connection.sendall(byte_buffer)
                data = client_connection.recv(4)
                val = int.from_bytes(data, 'little')
                print("Data size: %d" % val)
                data = client_connection.recv(val)
                print(data)
                with open(out_filename, 'wb') as f:
                    f.write(data)
                client_connection.close()
                print("Saved: " + out_filename)
            except socket.error:
                print("Could not connect to the socket. ")
            finally:
                client_connection.close()
    finally:
        s.close()

        
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
        
        
        
