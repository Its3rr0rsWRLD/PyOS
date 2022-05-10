import os
import sys
import time

if not os.path.exists("pass.txt"):
    with open("pass.txt", "w") as f:
        f.write("root")
print("""
Welcome to
    ╔═══╗   ╔═══╦═══╗
    ║╔═╗║   ║╔═╗║╔═╗║
    ║╚═╝╠╗ ╔╣║ ║║╚══╗
    ║╔══╣║ ║║║ ║╠══╗║
    ║║  ║╚═╝║╚═╝║╚═╝║
    ╚╝  ╚═╗╔╩═══╩═══╝
        ╔═╝║
        ╚══╝
               Terminal Version 1.0""")
print("\n")
input = input("Password: ")

# If input is equal to pass.txt, continue
if not input == open("pass.txt", "r").read():
    print("")
    print("Incorrect password")
    print("")
    time.sleep(2)
    os.system("clear")
    os.system("clear")
    os.system(sys.executable + " start.py")

if input == open("pass.txt", "r").read():
    os.system(sys.executable + " main.py")