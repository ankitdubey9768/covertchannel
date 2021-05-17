[!] legal disclaimer : Usage of this software for attacking targets or networks without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

# Introduction

For this assignment, we implemented a packet-sniffing packet backdoor that is designed to run covertly on a "compromised" host and give an attacker remote access to the machine without needing to authenticate with a valid username and password..

# Design

Our backdoor application consists of two modules, the backdoor itself and the command and control (C&C) server that is used to send commands to the backdoor for processing. Design details of each component are discussed in further detail below.

## Backdoor Design

The backdoor was designed with the idea that we should be able to get full shell access to the compromised machine through this backdoor.

The backdoor has these main functions/states:
	

* Sniff for TCP packets that have the src and dst port as 8505.

    * The C&C Server sends us it’s public key embedded in this packet.

* Attempt the port knocking routine when such a packet is received. 

    * Send the backdoor’s public key in the last port knock packet 

* After port knocking, attempt a reverse TCP connection to the host that sent the key packet

* Create a thread for communicating with the C&C Server

Once we have established a reverse TCP connection, we are able to send encrypted data back and forth between the backdoor and the C&C Server. 

Since the encryption library we used is only able to encrypt 245 bytes at a time, if our output exceeds 200, we will send the output back in encrypted ‘chunks’. This is useful for example if we want to send back the output of a less command where the requested file is large (exceeds 245 bytes). 

## FSM - Backdoor

![image alt text](/readme_images/image_0.png)

## C&C Server Design

The C&C server starts by running the **initializeFirewall.sh** script which configures iptables to drop all traffic at the INPUT, OUTPUT and FORWARD chains by default. The only traffic allowed are packets that meet the following criteria:

* outbound packets with TCP source port set to 80

* incoming packets that are from or related to a previously established connection with destination port set to 80

A raw socket is created to sniff all incoming/outgoing ethernet frames detected on the network card and second socket is created to listen on TCP port 80 for connection attempts from the backdoor. Epoll is used to monitor the sockets for activity and determine if any further processing must be done on packets. It will also allow the C&C server to scale to handle multiple backdoor connections if required in future iterations of the application.

The C&C server opens port 80 to TCP connections for 5 seconds when it receives a successful port knock from a backdoor host. For a port knock to be successful, the server must receive three TCP packets in the following order:

* Packet 1: SYN flag set, destination port set to 7005

* Packet 2: SYN flag set, destination port set to 8005

* Packet 3: SYN flag set, destination port set to 8505, backdoor’s public encryption key in payload

Port knocks are detected by having the sniffing port look for packets matching the characteristics above. When the first packet in the port knock is received, the C&C server starts a one second timer. If the port knock is not completed within this window the server does not open up port 80 to connections. If the port knock is completed successfully within this window however, the server inserts a new iptables rule to the INPUT chain to open up TCP port 80 for 5 seconds, before deleting the rule to close the port again.

A connection between the backdoor and server is established by having the C&C server send a crafted TCP packet to the backdoor with the source and destination ports set to 8505. The server’s public encryption key is included in the payload of this packet which the backdoor will use to encrypt its communications back to the server. Upon receiving this packet the backdoor will respond with its port knock. The C&C server receives the backdoor’s public encryption key in the 3rd packet of the port knock sequence which it will use to encrypt communications to the backdoor. After the port knock, the backdoor starts the TCP 3-way handshake to establish a connection with the server.

With a connection established, the C&C server can now send commands to the backdoor for processing. Both sides will use the respective public/private keys to encrypt and decrypt data throughout the session.

# Testing the Backdoor Application

To test our backdoor application, two VMs running Fedora 23 were set up in the following configuration on our test environment:

![image alt text](/readme_images/image_1.png)

To run the C&C server and backdoor components properly, the following Python packets have to be installed on the computer:

* PyCrypto (used for encryption)

* Scapy (used for packet crafting)

On Feodra 23, these can be installed by running the following commands

* **sudo dnf install pycrypto**

* **sudo dns install scapy**

To run the application, copy the contents of the **backdoor **folder to the PC that will act as the backdoor. In a terminal window, navigate to the folder and run the following command:

* **python backdoor.py**

On a separate PC, copy over the contents of the cncServer folder. Navigate to the folder in a terminal window and run the following command:

* **p****ython cncserver.py**

The C&C server will prompt you for the IP address of the backdoor and should connect successfully if the backdoor is running on that IP address.

## Test Cases

The following requirements were given for a successful backdoor implementation:

* The backdoor must camouflage itself so as to deceive anyone looking at the process table

* The application must ensure it only receives packets that are meant for the backdoor itself

* The backdoor must interpret commands sent to it, execute them and send the results back

* The backdoor must utilize an encryption scheme

Based on the requirements above, we came up with the test cases below to test the application against. Our results and discussion of each test case are presented in the following sections.

<table>
  <tr>
    <td>#</td>
    <td>Scenario</td>
    <td>Tools Used</td>
    <td>Expected Behavior</td>
    <td>Actual Behavior</td>
    <td>Status</td>
  </tr>
  <tr>
    <td>1</td>
    <td>Run backdoor stealthily on compromised host</td>
    <td>htop</td>
    <td>Backdoor camouflages itself in the process table</td>
    <td>Backdoor shows up in htop as "python backdoor.py"</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>2</td>
    <td>Send packet with valid protocol key to backdoor</td>
    <td>Python, Scapy, Wireshark</td>
    <td>Backdoor processes packet and sends port knock sequence</td>
    <td>Backdoor processes packet and sends port knock sequence</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>3</td>
    <td>Send packet with invalid protocol key to backdoor</td>
    <td>Python, Scapy, Wireshark</td>
    <td>Backdoor rejects packet and does no further processing</td>
    <td>Backdoor rejects packet and does no further processing</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>4</td>
    <td>Backdoor connecting to C&C server after correct port knock sequence</td>
    <td>Wireshark</td>
    <td>C&C server opens port 80 for 5 seconds after port knock and accepts TCP connection from backdoor before closing port 80 again</td>
    <td>C&C server opens port 80 for 5 seconds after port knock and accepts TCP connection from backdoor before closing port 80 again</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>5</td>
    <td>Backdoor connecting to C&C server after incorrect port knock sequence</td>
    <td>Wireshark</td>
    <td>C&C server does not open port 80 and no TCP connection is established</td>
    <td>C&C server does not open port 80 and no TCP connection is established</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>6</td>
    <td>Send encrypted packet containing shell command to backdoor</td>
    <td>Wireshark</td>
    <td>C&C server uses backdoor’s public key to encrypt command</td>
    <td>C&C server uses backdoor’s public key to encrypt command</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>7</td>
    <td>Send encrypted packet containing output from shell command to C&C server</td>
    <td>Wireshark</td>
    <td>Backdoor uses C&C server’s public key to encrypt output</td>
    <td>Backdoor uses C&C server’s public key to encrypt output</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>8</td>
    <td>“ls” command sent to backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor receives “ls” command </td>
    <td>Backdoor receives “ls” command  </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>9</td>
    <td>“cd” command sent to backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor receives “cd” command</td>
    <td>Backdoor receives “cd” command</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>10</td>
    <td>“iptables” command sent to backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor receives “cd” command</td>
    <td>Backdoor receives “cd” command</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>11</td>
    <td>“nslookup” command sent to backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor receives “nslookup” command </td>
    <td>Backdoor receives “nslookup” command </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>12</td>
    <td>“ip” command sent to backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor receives “ip” command </td>
    <td>Backdoor receives “ip” command </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>13</td>
    <td>“less” command sent to backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor receives “less” command </td>
    <td>Backdoor receives “less” command </td>
    <td>
Pass</td>
  </tr>
  <tr>
    <td>14</td>
    <td>“ls” output received from backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor sends output from “ls” command back to C&C server</td>
    <td>Backdoor sends output from “ls” command back to C&C server</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>15</td>
    <td>“cd” output received from backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor sends output from “cd” command back to C&C server</td>
    <td>Backdoor sends output from “cd” command back to C&C server</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>16</td>
    <td>“iptables” output received from backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor sends output from “iptables” command back to C&C server</td>
    <td>Backdoor sends output from “iptables” command back to C&C server</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>17</td>
    <td>“nslookup” output received from backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor sends output from “nslookup” command back to C&C server</td>
    <td>Backdoor sends output from “nslookup” command back to C&C server</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>18</td>
    <td>“ip” output received from backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor sends output from “ip” command back to C&C server</td>
    <td>Backdoor sends output from “ip” command back to C&C server</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>19</td>
    <td>“less” output received from backdoor</td>
    <td>Python, Sockets,
Command Line</td>
    <td>Backdoor sends output from “less” command back to C&C server</td>
    <td>Backdoor sends output from “less” command back to C&C server</td>
    <td>Pass</td>
  </tr>
</table>


### Test Case 1 - Run backdoor stealthily on compromised host

To confirm that the backdoor camouflages itself properly on the compromised host, we run it in a terminal window as follows:

Backdoor initialized: 

![image alt text](/readme_images/image_2.png)

If we open the terminal, we can find the application and see that it is showing up as the changed name. 
To demonstrate that we are able to mask the application name I have changed the process name to **notabackdoor. **This can be seen in the screenshot captured below. 

![image alt text](/readme_images/image_3.png)

### Test Case 2 - Send packet with valid protocol key to backdoor

For this scenario we used the C&C server on 192.168.1.161 to generate a packet with source and destination ports set to 8505, which is defined in the C&C server design section to be the valid protocol key. We then sent the packet to a host running the backdoor on IP address 192.168.1.100. Because the packet contains a valid protocol key, we expect to see the port knock sequence.

Using Wireshark to capture the session between both hosts, we saw the following activity take place:

![image alt text](/readme_images/image_4.png)

We see that after receiving the first packet, the backdoor responded with 3 packets back to the C&C server with their destination ports set to 7005, 8005 and 8505. Full details of the session are presented in the Wireshark capture titled **test case 2.pcapng**. As this is the port knock sequence we defined in the backdoor design section we can conclude that this test case passes.

### Test Case 3 - Send packet with invalid protocol key to backdoor

To test this scenario, we modified the C&C server to generate a packet with source port set to 8505 and destination port set to 31337. As this packet does not meet our definition of a valid protocol key, we expect to see no port knock response from the backdoor after receiving this packet.

Using Wireshark to capture the session between both hosts, we saw the following activity take place:

![image alt text](/readme_images/image_5.png)

We can see that after receiving the packet, the backdoor does not respond with any port knock sequence. Full details of the session are presented in the Wireshark capture titled **test case 3.pcapng**. However it is fairly obvious that this test case passes based on the results of the Wireshark capture.

### Test Case 4 - Backdoor connecting to C&C server after correct port knock sequence

The C&C server locks down the firewall to only allow traffic that meets the following conditions:

* outbound packets with TCP source port set to 80

* incoming packets that are from or related to a previously established connection with destination port set to 80

Running **iptables -L** shows these rules in action after the server has been initialized:

![image alt text](/readme_images/image_6.png)

Based on this rule set, it is impossible for any client to connect to the C&C server since you can’t establish an existing connection to the server before it starts. However, after specifying the IP address of the host running the backdoor, we see that the backdoor connects successfully as per the screenshot below:

![image alt text](/readme_images/image_7.png)

The Wireshark capture of this session also shows a successful TCP 3-way handshake between the C&C server on 192.168.1.161 and the backdoor on 192.168.1.100, providing further evidence of a successful connection.

![image alt text](/readme_images/image_8.png)

Running **iptables -L** on the C&C server right after the port knock has been received shows that TCP packets with a destination port of 80 are now allowed through on the INPUT chain, confirming that our port knock protocol is working as defined in the C&C server design section:

![image alt text](/readme_images/image_9.png)

Our design says that port 80 on the C&C server is left open for 5 seconds after a successful port knock, so we run iptables -L again to confirm that the port is blocked 5 seconds after the connection has been made and see the following:

![image alt text](/readme_images/image_10.png)

From these screenshots and the Wireshark capture, we can conclude that this test case passes.

### Test Case 5 - Backdoor connecting to C&C server after incorrect port knock sequence

For this test case, we modify the backdoor component to deliver a port knock with destination ports set to 7005/9001/8505 instead of the correct 7005/8005/8505 sequence. The Wireshark capture of the session is presented in the screenshot below:

![image alt text](/readme_images/image_11.png)

From the Wireshark capture, we see that the backdoor attempts connecting to the C&C server with a SYN packet after the port knock. However no connection is made as indicated by the subsequent TCP retransmissions, indicating that the C&C server did not open port 80. Full details of the session are presented in the Wireshark capture titled **test case 5.pcapng**

From this we conclude that this test case passes as the C&C server is only accepting connections with a valid port knock.

### Test Case 6 - Send encrypted packet containing shell command to backdoor

To test this scenario we started a backdoor session, sent the command **nslookup garykhoo.com** and got the response from the backdoor as can be seen in the screenshot below

![image alt text](/readme_images/image_12.png)

Wireshark was used to capture traffic for this session and full details are available in the Wireshark capture titled **test case 6.pcapng**. The packet with the command sent to the backdoor is the first one sent following the TCP 3-way handshake as highlighted in blue below:

![image alt text](/readme_images/image_13.png)

Looking at the payload of the packet, we see that it is all garbled up which indicates that the C&C server is using the backdoor’s public key to encrypt the command before sending it off.

![image alt text](/readme_images/image_14.png)

Based on this information, we can conclude that this test case is successful

### Test Case 7 - Send encrypted packet containing output from shell command to C&C server

Continuing on from Test Case 6, we saw that the **nslookup **command sent to the backdoor yielded a successful response. This indicates that the backdoor was able to successfully decrypt the command using its private key, encrypt the output with the C&C server’s public key and have the C&C server decrypt the response with its private key.

Looking further into Wireshark capture file **test case 6.pcapng**, we look closer at the packet containing the command output which is highlighted in blue.

![image alt text](/readme_images/image_15.png)

As was the case in Test Case 6, the output here is also garbled indicating that encryption was successful. We therefore conclude that this test case is successful.

![image alt text](/readme_images/image_16.png)

### Test Case 8 - "ls" command sent to backdoor

Backdoor receives ls and ls -l commands. 

![image alt text](/readme_images/image_17.png)

### Test Case 9 - "cd" command sent to backdoor

Here the backdoor has received two more commands: cd / and ls .

![image alt text](/readme_images/image_18.png)

### Test Case 10 - "iptables" command sent to backdoor

Backdoor receives iptables command with arguments.

![image alt text](/readme_images/image_19.png)

### Test Case 11 - "nslookup" command sent to backdoor

Backdoor receives nslookup command.

![image alt text](/readme_images/image_20.png)

### Test Case 12 - "ip" command sent to backdoor

Backdoor receives ip command

![image alt text](/readme_images/image_21.png)

### Test Case 13 - "less" command sent to backdoor 

Backdoor receives less command

![image alt text](/readme_images/image_22.png)

### Test Case 14 - "ls" output received from backdoor

We are able to list the directory of the compromised machine using the ls command as if you were on that machine or using ssh.

![image alt text](/readme_images/image_23.png)

### Test Case 15 - "cd" output received from backdoor

We send the command cd / to the compromised machine in order to get into the root directory.

After another ls command you can see that we are in the root directory of the compromised machine.

![image alt text](/readme_images/image_24.png)

### Test Case 16 - "iptables" output received from backdoor

Using the iptables command we can easily view and modify firewall rules of the compromised system. This would be a very handy tool for further compromising the machine with the backdoor.

Here is a snapshot of the beginning and end of the iptables output of our compromised machine. 

![image alt text](/readme_images/image_25.png)

![image alt text](/readme_images/image_26.png)

### Test Case 17 - "nslookup" output received from backdoor

We are able to also run nslookup on the compromised machine and receive data. 

![image alt text](/readme_images/image_27.png)

### Test Case 18 - "ip" output received from backdoor

We are able to capture interface information on the compromised machine as well through the ‘ip’ command. 

![image alt text](/readme_images/image_28.png)

### Test Case 19 - "less" output received from backdoor

Using the less command we are able to print out contents of files on the compromised machine. Using a similar command we would be able to also download files from the compromised machine. 

Output from large file:![image alt text](/readme_images/image_29.png)

Output from Small sample file: 

![image alt text](/readme_images/image_30.png)

# Conclusion

We have been able to produce a backdoor that can give an attacker complete shell access of the compromised machine. Our backdoor easily gives the attacker as much access as SSH would. With a backdoor such as this we can modify firewall rules, navigate and list directories. Read and download files from the compromised machine. 


Using commands such as nmap, we would also be able to perform reconnaissance on the compromised machine’s network in order to further our attack.

One shortcoming with our current implementation is that the backdoor cannot run commands that require further user interaction before the command completes, so commands like **dnf **that prompt for confirmation after running the initial command will cause the C&C server to stall as the command never finishes running on the backdoor. An improved iteration of our application would be to include support for running these interactive commands. Our application also requires the installation of python and pycrypto in order to work.

With that in mind though, we have provided a very elaborate proof of concept in python and have demonstrated the various concepts covered in class. Any real world implementation of our back door would be done in a language such as C and will have no need of installing packages and will be much more easily concealed. 

