from logging import root
import os
import yara
from os.path import exists
import shutil
import glob


def find_files(filename, search_path):
   result = []
   for root, dir, files in os.walk(search_path):
      if filename in files:
         result.append(os.path.join(root, filename))
   return result

def main():
    print("STARTING THE SCANNER")
    dir_path = r'**/setup.py'
    match_dir = glob.glob(dir_path)
    rule = yara.compile('./yara-rules/rules.yar')
    for i in range(len(match_dir)):
        match = rule.match(match_dir[i])
        if (len(match) >= 1):
            #print(type(match))
            print("Title: " + match_dir[i].replace("\setup.py",""))
            print("Rules matched on:[", end = "")
            #print(len(match["main"]))
            for m in range (len(match["main"])):
                print(str(match["main"][m]["rule"])+ ",", end = "")
            print("]")
            print("Malicious file paths:[", end = "")
            print(match_dir[i], end="]")
            print("\n-------------------")
        else:
            print('no match')
            #print(res[i])
            print(match_dir[i].replace('\\setup.py',''))
            shutil. rmtree(match_dir[i].replace('\\setup.py',''))
    print("STOPPING THE SCANNER")

def main_js():
    print("STARTING THE SCANNER")
    dir_path = 'C:/Users/17142/Desktop/Cyber/Package/deltastealer/src/delta/injection.js'
    match_dir = glob.glob(dir_path)
    rule = yara.compile('./yara-rules/rules.yar')
    for i in range(len(match_dir)):
        match = rule.match(match_dir[i])
        if (len(match) >= 1):
            #print(type(match))
            print("Title: " + match_dir[i].replace("\setup.py",""))
            print("Rules matched on:[", end = "")
            #print(len(match["main"]))
            for m in range (len(match["main"])):
                print(str(match["main"][m]["rule"])+ ",", end = "")
            print("]")
            print("Malicious file paths:[", end = "")
            print(match_dir[i], end="]")
            print("\n-------------------")
        else:
            print('no match')
            #print(res[i])
            print(match_dir[i].replace('\\setup.py',''))
            shutil. rmtree(match_dir[i].replace('\\setup.py',''))
    print("STOPPING THE SCANNER")
main_js()
'''
print("STARTING THE SCANNER")
dir_path = r'**/setup.py'
match_dir = glob.glob(dir_path)
rule = yara.compile('./rules.yar')
for i in range(len(match_dir)):
    match = rule.match(match_dir[i])
    if (len(match) >= 1):
        #print(type(match))
        print("Title: " + match_dir[i].replace("\setup.py",""))
        print("Rules matched on:[", end = "")
        #print(len(match["main"]))
        for m in range (len(match["main"])):
            print(str(match["main"][m]["rule"])+ ",", end = "")
        print("]")
        print("Malicious file paths:[", end = "")
        print(match_dir[i], end="]")
        print("\n-------------------")
    else:
        print('no match')
        #print(res[i])
        print(match_dir[i].replace('\\setup.py',''))
        shutil. rmtree(match_dir[i].replace('\\setup.py',''))
print("STOPPING THE SCANNER")
'''