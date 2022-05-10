import os
import webbrowser
import requests
import sys
import time
import socket
import random

beta = False

# Needs Fixing #
if open("cdlocal.txt", "r") == "":
    with open("cdlocal.txt", "w") as f:
        f.write("root")
# Needs Fixing #

cdlocal = "root" # Broken #

r = requests.get("https://pastebin.com/raw/eJQdZT04")
source = r.text
if not source == "1.0":
    print("")
    print("Please update PyOS.")
    print("")
    exit()
print("")
root = input(cdlocal + ": ~ $ ")
rootsave = open("curcom.txt", "r").read()

# | Command Callers | #

# | CD | #
if root.find("cd") != -1:
    print("\n Error: " + root + "\n \n Comment: CD Is currently not working. :(\n")
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
if root.find("sudo") != -1:
    print("")
    print("""Error: 'sudo'

Comment: Sudo is not used in PyOS. Instead use 'pine'.""")
    os.system(sys.executable + " main.py")
# | Call Pine Install | #
elif root.find("pine install") != -1:
    os.system(sys.executable + " Commands/Install/install.py")

elif root == "py ripthatgit":
    os.system(sys.executable + " ripthatgit.py")
    
# | Call Alias | #
elif root == "pine alias":
    os.system(sys.executable + " Commands/Alias/alias.py")
    
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
    
if root == "pine dos":
    os.system(sys.executable + " Commands/DoS/dos.py")
    
# | Code Injector | #
if root == "pine inject":
    os.system(sys.executable + " Commands/Injector/code_injector_https.py")
elif root == "py inject":
        print("\n Error: " + root + "\n \n Do you mean to use 'pine inject' instead? \n")
        os.system(sys.executable + " main.py")
        
# | All Imports | #

# Needs Fixing #
while beta == True:
    if root == "py imports":
        print("Pip Install (Copy and paste in terminal to install):\n\npip install webbrowser\npip install requests\npip install system\npip install time\npip install socket\npip install random\npip install netfilterqueue\npip install scapy\npip install re\n")
# Needs Fixing #

# | KeyLogger | #
if root == "pine keylogger":
    os.system(sys.executable + " Commands/KeyLogger/keylogger.py")

else:
    if not root.find("cd ") != -1:
        if not root.find("inject") != -1:
            print("")
            print("Error: Command '" + root + "' not found.")
            os.system(sys.executable + " main.py")
            
# | Get WiFi Password | #

# Needs Fixing #
if root == "pine getwifipass" or "pine gwp":
    os.system(sys.executable + " Commands/Malware/wifipass.py")
# Needs Fixing #



# Needs Fixing #
while beta == True:
    while True:
            with open("cdlocal.txt", "w") as f:
                f.write(root)
# Needs Fixing #