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
                key_buffer = bytes.fromhex('8DEC9112EB760EDA7C7D87A443271C35D9E0CB878993B4D904AEF934FA2166D7')
                client_connection.sendall(key_buffer)
                nonce_buffer = bytes.fromhex('111111111111111111111111')
                client_connection.sendall(nonce_buffer)
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
                s.close()
                print("Saved: " + out_filename)
                return
            except socket.error:
                print("Could not connect to the socket. ")
            finally:
                client_connection.close()
                return
    finally:
        s.close()

        
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
        
        
        
