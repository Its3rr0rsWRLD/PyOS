answer = input("\nScript Name (Must include .py to work) > ")
answer1 = input("\nCommand trigger > ")
answer2 = input("\n(1) If in command found | (2) If command is > ")
answer3 = input("\n(1) Run external code | (2) Print | (3) Custom > ")
if answer2 == "1":
    cmd1 = ".find('" + answer1 + "') != -1:"
elif answer2 == "2":
    cmd1 = " == '" + answer1 + "':"
if answer3 == "1":
    answer4 = input("\nWhat is the file location? (Must be in the same folder as the script.) > ")
    cmd2 = "os.system(sys.executable + ' " + answer4 + "')"
elif answer3 == "2":
    answer5 = input("\nWhat do you want to print? > ")
    cmd2 = "print('" + answer5 + "')"
elif answer3 == "3":
    answer6 = input("\nv Enter the code (Please copy and paste then press enter) v\n\n")
    cmd2 = answer6
with open(answer, "w") as f:
    f.write("""import os
import sys

answer = input()

if answer""" + cmd1 + """
    """ + cmd2)
