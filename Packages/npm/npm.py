import os
import sys
import webbrowser

with open("npm.txt", "r") as f:
    for line in f:
        print("")
        line = line.strip()
        os.system("npm install " + line)
        os.system(sys.executable + " main.py")
