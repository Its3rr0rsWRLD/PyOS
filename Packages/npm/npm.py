import os
import sys
import webbrowser

with open("npm.txt", "r") as f:
    for line in f:
        line = line.strip()
        os.system("npm install " + line)
        print("\nInstalled " + line)
        os.system(sys.executable + " main.py")
