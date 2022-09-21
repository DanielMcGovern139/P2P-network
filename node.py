from ast import arg
import pickle
import socket
import threading
import hashlib
import os
import csv
import sys
from typing import NamedTuple


# parses user input untill the user is logged in 
def initialize_login():

    loggedin = False

    while not loggedin:

        action = input('For logging in the server , please type "login". \nIf you are a new user , type "create" to make an account.\nFor deleting an account , type "delete". :')
        if action == 'create':
            acc_creation()

        elif action == 'login':
            loggedin = userlogin()

        elif action == 'delete':
            acc_delete()

        else:
            print("Invalid command ")

# writes the credentials input by the user to the file 
def acc_creation(file="credentials.txt"):
    user = input('username: ')
    passw = input('password: ')

    with open(file, 'a') as f:
        f.write(to_encrypt(user) + ',' + to_encrypt(passw) + '\n')

# removes user from both memory and file itself
def acc_delete(file="credentials.txt"):
    account = input('Please input account you want to delete?: ')
    passw = input("Input password to verify: ")

    with open(file, 'r') as f:
        text = f.read()

    text = text.replace(to_encrypt(account) + ',' + to_encrypt(passw), '')

    with open(file, 'w') as f:
        f.write(text)

# checks data input by the user against the credentials file
def userlogin(file='credentials.txt'):
    account = input('username: ')
    passw = input("password: ")

    with open(file, 'r') as f:
        text = f.read()

    find_account = text.find(to_encrypt(account) + ',' + to_encrypt(passw) + '\n')

    if find_account != -1:
        print('Hey welcome to the server, ' + account)
        return True
    else:
        print('Incorrect Password or Invalid user detected')
        return False


# encrypts user credentials
def to_encrypt(str):
    encrypchar = ''

    for char in str:
        if char != 'r' or char != 't':
            encrypchar += chr(ord(char) + 15)
        elif char == 'r':
            encrypchar += 'a'
        elif char == 't':
            encrypchar += 't'

    return encrypchar


HEADER = 64                             # header in front of every message containing the message length
PORT = 33500                            # port the listening thread is run on 

# if ip is passed as an argument when the file is run, the node run on said ip, otherwise it will use the normal ip of the machine

if len(sys.argv) > 1:
    NODE = sys.argv[1]
else:                      
    NODE = socket.gethostbyname(socket.gethostname())

ADDR = (NODE, PORT)
FORMAT = 'utf-8'                        # format of the messages 

#list of command indexes for connection handling
JOIN = "0x0"
MESSAGE = "0x1"
PEERLIST_UPDATE = "0x2"
PEERLIST_REPLACE = "0x3"
REQUEST_FILE= "0x4"
SEND_FILE = "0x5"
LEAVE = "0x9"

# dictionary to store information of all nodes connected to the network 
peerlist = []

#initialise listening socket
node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
node.bind(ADDR)

buffer = 4096

#class to store node information
class client(NamedTuple):
    ip: int
    id: str

# each node gets an ID generated using SHA256
def generate_id(addr):
    _value = str(addr)
    result = hashlib.sha256(_value.encode(FORMAT))
    return  result.hexdigest()

# utility function to show all nodes on screen
def print_peers():
    list = '\nConnected clients:\n'
    for x in peerlist:
        list = list  + str(x.id) +  " ip: " + str(x.ip) + "\n"
    return str(list)

# updates all the nodes with the new peerlist
# starts clienthreads with PEERLIST UPDATE argument for each node in the peerlist 
def update_peerlists():
    print("updating peerlists...")

    thread_list = []
    for x in peerlist:
        if x.ip[1] == NODE:
            continue

        message = "peerlist " + str(x.id)
        args = message.split()
        thread = threading.Thread(target=client_thread, args=(PEERLIST_UPDATE,args))
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

# replaces all the nodes with the new peerlist
# similar to update_peerlists, starts clientthreads with PEERLIST REPLACE argument 
def replace_peerlists():
    print("replacing peerlists...")

    replace_thread_list = []
    for x in peerlist:
        if x.ip[1] == NODE:
            continue

        message = "peerlist " + str(x.id)
        args = message.split()
        thread = threading.Thread(target=client_thread, args=(PEERLIST_REPLACE,args))
        replace_thread_list.append(thread)

    for thread in replace_thread_list:
        thread.start()

# generates id for the node and appends it to the peerlist
def addNode(addr):
    newid = generate_id(addr)
    peerlist.append(client(id = newid, ip=addr))

# removes the node from the peerlist
def removeNode(id):
    print("Removing node " + str(id))
    i = 0   #index of the client in question
    for x in peerlist:
        if x.id == id:
            #remove from list
            peerlist.pop(i)
        i+=1

# utility functions for finding nodes

def find_node_id(addr):
    for x in peerlist:
        if addr == x.addr:
            return x.id
    return 0 #node not found

def find_node_ip(id):
    for x in peerlist:
        if id == x.id:
            return x.ip
    return 0 #node not found

def find_node(peer):
    for x in peerlist:
        if x == peer:
            return 1
    
    return 0

#utility functions for parsing and working with messages

def get_message(args):
    result = ''
    for x in args:
        result += str(x) + ' '
    return result 

def recieve_message(args):
    if len(args) > 1:
        print(str(args[1]) + " : ")
        message = get_message(args[2:])   
        print(message)       

# this function is called for almost all interactions between the nodes in the clientThreads

def send(msg, reciever):
    print("sending...")
    message = msg.encode(FORMAT)

    #create a header from the message length
    msg_length = len(message)                           
    send_length = str(msg_length).encode(FORMAT)        
    send_length += b' ' * (HEADER - len(send_length))   

    #send header and the message
    reciever.send(send_length)                            
    reciever.send(message)    
    print("sent...")            



#---------------------------------------------------------------------------
#--------------------------------PEERLIST HANDLING--------------------------
#---------------------------------------------------------------------------

def send_peerlist(peer):
    print("pickling peerlist")
    print("sending peerlist...")
    peer.sendall(pickle.dumps(peerlist))
    print("peerlist sent")

# replaces your peerlist with a new one from the node that called replace_peerlists
def replace_peerlist(newpeerlist):
    self = peerlist[0]
    peerlist.clear()
    peerlist.append(self)
    for x in newpeerlist:
        if find_node(x) == 1:
            continue
        peerlist.append(x)

# appends your peerlist with a new one from the node that called update_peerlists
def append_peerlist(newpeerlist):

    if newpeerlist:
        for x in newpeerlist:
            if find_node(x) == 0:
                peerlist.append(client(ip = x.ip, id = x.id))



#---------------------------------------------------------------------------
#--------------------------------MAIN-THREADS-------------------------------
#---------------------------------------------------------------------------

# function to parse the message recieved by the listening thread.
# each command index results in a different behaviour of the reciever

def parse_message(conn, addr, msg_length):
    print("Parsing message...")
    msg_length = int(msg_length)
    msg = conn.recv(msg_length).decode(FORMAT) # recieve message from the client node

    args = msg.split()

    # each message has a command index at the front and arguments after, all divided by spaces
    # each function requires different arguments and the bahaviour of the listening node is different for each command

    if args:
        if args[0] == JOIN:
            print("New peer joinig...")
            listeningaddr = pickle.loads(conn.recv(buffer))     # load the address of the joining node from the recieved buffer
            addNode(listeningaddr)                              # add node to local peerlist
            send_peerlist(conn)                                 # send the peerlist back to the joining node
            newpeerlist = pickle.loads(conn.recv(buffer))       # recieve the joining node peerlist 
            append_peerlist(newpeerlist)                        # append local peerlist with entries that are on the joining node peerlist but not on the local
            update_peerlists()                                  # send the new peerlist to all connected nodes
            
        elif args[0] == MESSAGE:
            recieve_message(args)                               # parse the contents of the message
            
        elif args[0] == PEERLIST_UPDATE:
            newpeerlist = pickle.loads(conn.recv(buffer))       # load the new peerlist from the recieved buffer
            append_peerlist(newpeerlist)                        # append local peerlist with entries that are on the other node peerlist but not on the local
            print("peerlist updated")

        #called when a node leaves the network
        elif args[0] == PEERLIST_REPLACE:
            newpeerlist = pickle.loads(conn.recv(buffer))       # load the new peerlist from the recieved buffer
            replace_peerlist(newpeerlist)                       # append local peerlist with entries that are on the other node peerlist but not on the local
            print("peerlist replaced")

        # recieves the file request from other node
        elif args[0] == REQUEST_FILE:

            # format: REQUEST_FILE [filename]

            print("download request")
            
            filename = args[2]                      # second argument is the filename 
            filename = os.path.basename(filename)   

            if len(args) > 2:

                if os.path.isfile(filename):
                    thread = threading.Thread(target=client_thread, args=(SEND_FILE,args))  #if file exists, send file to requesting node
                    thread.start()
                else:
                    print("file not found")
            else:
                print("not enough arguments")

        elif args[0] == SEND_FILE:

            # format: SEND_FILE [filename] [filesize]

            filename = args[1]
            filesize = args[2]
            filename = os.path.basename(filename)
            filesize = int(filesize)

            print("downloading file " + str(filename) + " of size " + str(filesize))

            # recieves the file in buffer sized chunks
            with open(filename, "wb") as f:
                while True:
                    
                    bytes_read = conn.recv(buffer)
                    if not bytes_read:    
                        break

                    f.write(bytes_read)

        elif args[0] == LEAVE:

            #format: LEAVE [recieving node address] [leaving node address]

            if len(args) > 2:
                print("removing " + args[2])
                print(str(args[2]))
                if find_node_ip(args[2]) != 0:          
                    removeNode(args[2])             # remove node in local peerlist
                    replace_peerlists()             # replace peerlists of all other nodes
                    print("node removed")
                else:
                    print("node not found")
            else:
                print("no node specified to be removed")

    else:
        conn.send("wrong command".encode(FORMAT))  # send wrong command message to the client node

# handler for each node that connects to the listening thread

def handle_connection(conn, addr):
    print("connection opened")
    while True:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            break
        except ConnectionResetError:
            print("connection interrupted")
            break
# if there is a message, parse message
    if msg_length:
        parse_message(conn,addr,msg_length)
        conn.close()
        print("connection closed")

# main listening thread of the application
# creates a handle connection thread for each new connection it accepts

def listen_thread():
    node.listen()
    print("listening...")
    while True:
        conn, addr = node.accept()
        print("new connection")
        thread = threading.Thread(target=handle_connection, args=(conn, addr))
        thread.start()

# main sending thread of the application
# invoked for every interaction between the node that this node connects to 

def client_thread(command,args):
    print("sending " + str(command))

    # most arguments from the command thread have the second arguent as the hash of the node we are sending to
    # join uses an ip as the second argument, therefore the ip is set straight away
    # leave does not take second arguments, but rather finds the reciever node in its peerlist
    # all other functions find the ip of the node based on hash

    #get address to connect to
    if command == JOIN:
        if  len(args) > 1:
            ip = args[1]
        else:
            print("you have to give the ip address you are trying to join to...")
            return
    elif command == LEAVE:
        if len(peerlist) > 1:
            addr = find_node_ip(peerlist[1].id) # find ip of the node we are connecting to based on hash
            if addr == 0:
                print("invalid node")
            else:
                ip = addr[0]
        else:
            print("You are currently not in any network")
            return
    else:
        if len(args) > 1:
            addr = find_node_ip(args[1]) # find ip of the node we are connecting to based on hash
            if addr == 0:
                print("invalid node")
            else:
                ip = addr[0]

    if ip:
        print("to " + str(ip))

    # after the ip is set, connect to the node and execute different functionality based on the function 
    while True:
        try:
            addr = (ip, PORT)
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer.connect(addr)
            print("connected to " + str(addr))
            break

        except Exception:
            print("Can't connect :(, Try again\n")
            return
    
    if command == PEERLIST_UPDATE:
        send(PEERLIST_UPDATE,peer)                  # send peerlist update message to reciever
        print("sending peerlist to " + str(peer))  
        send_peerlist(peer)                         # send the peerlist to the reciever

    elif command == PEERLIST_REPLACE:
        send(PEERLIST_REPLACE,peer)                 # send peerlist replace message to reciever
        print("sending peerlist to " + str(peer))
        send_peerlist(peer)                         # send the peerlist to the reciever


    elif command == MESSAGE:
        message = ''
        for x in args[2:]:
            message += str(x) + ' '
        send(MESSAGE + ' ' + peerlist[0].id + ' ' + message,peer)   # send the message 


    elif command == JOIN:
        send(JOIN + ' ' + args[1],peer)                 # send join message
        peer.sendall(pickle.dumps(ADDR))                # send pickled address of this node to reciever
        newpeerlist = pickle.loads(peer.recv(buffer))   # get new peerlist from the reciever
        append_peerlist(newpeerlist)                    # append local peerlist
        peer.sendall(pickle.dumps(peerlist))            # send the local peerlist to the reciever
        list = print_peers()                         
        print(str(list))                                # print new peerlist on screen 
            

    elif command == LEAVE:
        if len(peerlist) > 1:
            send(LEAVE + ' ' + peerlist[1].id + ' ' + peerlist[0].id,peer)      # send leave message to the reciever
            newpeerlist = []                                                    # empty local peerlist 
            replace_peerlist(newpeerlist)                                       # empty local peerlist
    
    elif command == REQUEST_FILE:
        if len(args) > 2:
            filename = args[2]                                                      # get filename from the second argument in the command thread
            send(REQUEST_FILE + " " + peerlist[0].id + " " + str(filename),peer)    # send the request file message with the name of the file attached

    elif command == SEND_FILE:
        if len(args) > 2:
            print("sending file...")
            filename = args[2]                                                      # get filename from the second argument in the command thread
            filesize = os.path.getsize(filename)                                    # get the size of the file 
            send(SEND_FILE + " " + str(filename) + " " + str(filesize),peer)        # send send file message to reciever with filename and filesize attached 
            
            # recieves the file in buffer sized chunks until the file is empty
            with open(filename, "rb") as f:                        
                while True:
                    bytes_read = f.read(buffer)

                    if not bytes_read:
                        break

                    peer.sendall(bytes_read)

            print("file sent!")
        else:
            print("no filename given")

    else:
        print("wrong command in clientthread")
    peer.close()


# takes user input and parses it to the clientThread when it is required, based on the first argument of the input string 
def command_thread():

    while True:
        message = input()           #wait for keyboard input
        args = message.split()      #split message into arguments
        if args:
            if args[0] == "join":
                thread = threading.Thread(target=client_thread, args=(JOIN,args))
                thread.start()
            elif args[0] == "send":
                thread = threading.Thread(target=client_thread, args=(MESSAGE,args))
                thread.start()
            elif args[0] == "peerlist":
                list = print_peers()
                print(str(list))
            elif args[0] == "leave":
                thread = threading.Thread(target=client_thread, args=(LEAVE,args))
                thread.start()
            elif args[0] == "update_peerlist":
                thread = threading.Thread(target=client_thread, args=(PEERLIST_UPDATE,args))
                thread.start()
            elif args[0] == "send_file":
                thread = threading.Thread(target=client_thread, args=(SEND_FILE,args))
                thread.start()
            elif args[0] == "download_file":
                thread = threading.Thread(target=client_thread, args=(REQUEST_FILE,args))
                thread.start()
            elif args[0] == "help":
                print("join [peer ip] - joins the network through peer already in the network")
                print("peerlist - shows all peers in the network")
                print("send [reciever id] [message] - sends message to a specified peer")
                print("send_file [reciever id] [filename] - sends file to a peer")
                print("download_file [reciever id] [filename] - downloads a file from a peer")
                print("leave [peer id] - leaves the network through peer id")
            else:
                print("wrong command, type help for command list")

# this function ensures that the first node in the peerlist is yourself
def join_self():                
    message = "join "+ NODE
    args = message.split()
    thread = threading.Thread(target=client_thread, args=(JOIN,args))
    thread.start()

# function that starts the node
def start():
    initialize_login()                                      # start login funcion 
    listenThread = threading.Thread(target=listen_thread)   # start listening thread on 33500
    listenThread.start()
    join_self()                                             # join self
    commandThread = threading.Thread(target=command_thread) # start the command thread
    commandThread.start()
    os.system('cls')                                        # clear screen from the output mess made by the previous functions
    print("Client Started\nIP: " + str(NODE))               



start()
