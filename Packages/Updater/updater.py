import requests
import time
import sys
import os

r = requests.get('https://raw.githubusercontent.com/ThatError404/PyOS/main/latest-version.txt')
version = r.text

if int(version) > 2:
    print('\nUpdate available! Latest Version: ' + version)
    answer = input("\nDo you want to update? (y/n) ")
    if answer == "y" or answer == "Y":
        print("\nDownloading...")
        sversion = version.split("\n")
        r = requests.get('https://raw.githubusercontent.com/ThatError404/PyOS/main/PyOS-' + sversion[0] + '/PyOS.py')
        with open("PyOS-V" + sversion[0] + ".py", 'w') as f:
            f.write(r.text)
        if not os.path.exists("PyOS-V" + sversion[0] + ".py"):
            print("\nError: Download failed.\n\nError: Write Unsuccessful.\n\nPlease contact the developer.")
            exit()
        elif os.path.exists("PyOS-V" + sversion[0] + ".py"):
            print("\nDownload successful.\n\nUpdating...")
            time.sleep(1)
            os.system(sys.executable + "PyOS-V" + sversion[0] + ".py")
