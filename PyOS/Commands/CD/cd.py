import os
import sys

root = open("curcom.txt", "r").read()
curcd = root.split("cd ")[1]
with open("cdlocal.txt", "w") as f:
    f.write(curcd)
os.system(sys.executable + " main.py")