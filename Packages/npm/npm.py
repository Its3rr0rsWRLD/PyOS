import os
import sys
import webbrowser

question = input("\nDo you have Node.js installed? (Y/N)")
if question == "y" or question == "Y":
  with open("npm.txt", "r") as f:
    for line in f:
        line = line.strip()
        os.system("npm install " + line)
        print("Installed " + line)
        os.system(sys.executable + " main.py")
if question == "n" or question == "N":
    answer = input("What platform are you on? (Mac/Windows) > ")
    if answer == "mac" or answer == "Mac":
        webbrowser.open("https://nodejs.org/dist/v16.15.0/node-v16.15.0.pkg")
    elif answer == "windows" or answer == "Windows":
        webbrowser.open("https://nodejs.org/dist/v16.15.0/node-v16.15.0-x86.msi")
                    
    print("\nPlease install Node.js, then run this again.")
                    
    os.system(sys.executable + " main.py")
