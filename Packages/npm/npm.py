import os
import webbrowser

answer = input("What platform are you on? (Mac/Windows) >")
if answer == "mac" or answer == "Mac":
  webbrowser.open("https://nodejs.org/dist/v16.15.0/node-v16.15.0.pkg"
elif answer == "windows" or answer == "Windows:
  webbrowser.open("https://nodejs.org/dist/v16.15.0/node-v16.15.0-x86.msi"
                  
os.system(sys.executable + " main.py")
