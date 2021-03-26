from common_helper_process import execute_shell_command
from pathlib import Path


#test =execute_shell_command(checksec --file=/bin/ls)

#import subprocess
import json
#import re
dir_checksec = Path(__file__).parent.parent
print(str(dir_checksec))
shell_skript= dir_checksec/'shell_skript/checksec'
print(str(shell_skript))
install_shell_skript = dir_checksec/'install.sh'
print(str(install_shell_skript))
file_pfad = dir_checksec/'test/data/Hallo_cfi'


p = execute_shell_command(str(shell_skript) + ' --file=' + str(file_pfad) +' --format=json --extended')  

print (p)


pbib= json.loads(p)

print(f'das ist ein test')

print(f"das ist Relro: {str(pbib[str(file_pfad)]['relro'])}.")

if pbib[str(file_pfad)]['fortify_source']=="no":
    print("WORKS!!!")
else:
    print("ERROR!!!!!!!!")


#pbib = json.loads(j)

#print pbib
#for line in p.stdout.readlines():
#   print line,
