import os
import sys

class ConsoleColors:
                    HEADER = '\033[95m'
                    OKBLUE = '\033[94m'
                    OKGREEN = '\u001b[32m'
                    WARNING = '\033[93m'
                    FAIL = '\033[91m'
                    BOLD = '\033[1m'
                    
print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + """

Welcome to                                                            
        ,-.----.                        ,----..               
        \    /  \                      /   /   \   .--.--.    
        |   :    \                    /   .     : /  /    '.  
        |   |  .\ :                  .   /   ;.  \  :  /`. /  
        .   :  |: |                 .   ;   /  ` ;  |  |--`   
        |   |   \ :    .--,         ;   |  ; \ ; |  :  ;_     
        |   : .   /  /_ ./|         |   :  | ; | '\  \    `.  
        ;   | |`-', ' , ' :         .   |  ' ' ' : `----.   \ 
        |   | ;  /___/ \: |         '   ;  \; /  | __ \  \  | 
        :   ' |   .  \  ' |          \   \  ',  / /  /`--'  / 
        :   : :    \  ;   :           ;   :    / '--'.     /  
        |   | :     \  \  ;            \   \ .'    `--'---'   
        `---'.|      :  \  \            `---`                 
        `---`        \  ' ;                                  
                        `--`                                   
                                                Update 2.0\n\n""")
os.system(sys.executable + " main.py")
