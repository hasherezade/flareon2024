import socket
import sys
import argparse
import struct

connection = None
xor_key = bytes.fromhex('133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337')

def print_hex_dump(buffer):
    hex_data = " ".join("%02x" % b for b in buffer)
    print(hex_data)
    
def xor_buffers(buffer1, buffer2):
    result = bytes()
    for i in range(min(len(buffer1), len(buffer2))):
        result += bytes([buffer1[i] ^ buffer2[i]])
    return result
   
def print_bigint(data):
    #print(data)
    print_hex_dump(data)
    print("XORed: ")
    print_hex_dump(xor_buffers(data, xor_key))
    print("---")
    
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
                    data = client_connection.recv(48)
                    print("Received: %d bytes" % len(data))
                    print_bigint(data)
                    
                    data = client_connection.recv(48)
                    print("Received: %d bytes" % len(data))
                    print_bigint(data)
                    
                    out = bytes.fromhex('A0D2EBA817E38B03CD063227BD32E353880818893AB02378D7DB3C71C5C725C6BBA0934B5D5E2D3CA6FA89FFBB374C3196A35EAF2A5E0B430021DE361AA58F8015981FFD0D9824B50AF23B5CCF16FA4E323483602D0754534D2E7A8AAF8174DC')
                    print("Sending: %d bytes" % len(out))
                    print_bigint(out[0:len(xor_key)])
                    print_bigint(out[len(xor_key):])
                    client_connection.sendall(out)
                    buffer_verify = bytes.fromhex('7665726966790000000000000000000000000000')
                    client_connection.sendall(buffer_verify)
                    while True:
                        buffer2 = bytes.fromhex('31')
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
