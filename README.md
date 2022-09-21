This was a group project completed as part of the 3D3 computer networks module in Trinity College Dublin.  

It is a p2p network with various different functionalities described below.

To Run node.py, all you need is python 3.9 or above installed. No other libraries and dependencies are required.

For optimal perfomance Run with two or more nodes. To open node.py enter python node.py followed by the nodes ip.
For example python node.py 127.0.0.1

Login into the network

1. Type 'create' to create a username and password
2. Then enter 'login' with this username and password
3. If the username or password is incorrect you will be asked to re-enter 
3. Once logged a Client Started followed by your Ip address will be shown on your terminal


Join another node

1. To join another node type 'join IP', IP being the ip address of the node you wish to join
2. A successful connection message should display on your screen and you are now connected 
3. A peerlist will also be displayed on your screen showing the other nodes connected on the network


Get the peerlist 

1. Type 'peerlist' and you will recieve a list of peers connected on the network
2. The peers ID will display along with their IP address and port number 

Send a message 

1. To send a message to another node enter 'send PeerID message'
2. To retrieve the nodes Peer ID see the peerlist which shows each IP address along with the corresponding PeerID
2. This will send a message to the node with that peer ID and the message will display on the 
   receivers terminal

Send a file

1. To send a file to another node enter 'send_file PeerID filename' 
2. This will send a file to the node with that PeerID
3. A message will be displayed on your screen saying the file was sent
3. A message will be displayed on the receivers terminal indicatating the file is downloading

Download a file

1. To download a file from a node enter 'download_file PeerID filename'
2. This will download the requested file and a message will be displayed on the nodes terminal 

Leave the network

1. To leave the network enter 'leave'. You will now be disconnected from the network and the peerlist
   will be updated to reflect this.
2. If another node enters 'peerlist', the node that just left will no longer appear in the peerlist 




