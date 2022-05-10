import os
import webbrowser
import requests
import sys

root = open("curcom.txt", "r").read()

if root.find("pine install") != -1:
    package = root.split("pine install ")[1]
    if package == "" or package == " ":
        print("")
        print("Error: Package name not found.")

        os.system(sys.executable + " main.py")
    elif not package == "":
        print("")
        if package in open("packages.txt", "r").read():
            with open("packages.txt", "r") as f:
                url = f.read().split(package + " ")[1]
                webbrowser.open(url)
                print("")
                print("Installed " + package + " successfully. Please move the file in to Packages/.")
                print("")
                print("Restarting...")
                os.system(sys.executable + " main.py")