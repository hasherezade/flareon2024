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
                    # print the received client coordinates:
                    data = client_connection.recv(48)
                    print("Received: %d bytes" % len(data))
                    print_bigint(data)
                    data = client_connection.recv(48)
                    print("Received: %d bytes" % len(data))
                    print_bigint(data)
                    # send the PCAP fragment, containing the server coordinates and the encrypted 'verify' keyword:
                    out = bytes.fromhex('a0d2eba817e38b03cd063227bd32e353880818893ab02378d7db3c71c5c725c6bba0934b5d5e2d3ca6fa89ffbb374c3196a35eaf2a5e0b430021de361aa58f8015981ffd0d9824b50af23b5ccf16fa4e323483602d0754534d2e7a8aaf8174dcf272d54c31860f')
                    print("Sending: %d bytes" % len(out))
                    client_connection.sendall(out)
                    data = client_connection.recv(48)
                    print("Received MSG: %d bytes" % len(data))
                    print_hex_dump(data)
                    # dummy command loop:
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
