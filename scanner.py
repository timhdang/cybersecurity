from logging import root
import os
import yara
from os.path import exists
import shutil
import glob
from termcolor import colored
import pathlib
from pathlib import Path
def find_files(filename, search_path):
   result = []
   for root, dir, files in os.walk(search_path):
      if filename in files:
         result.append(os.path.join(root, filename))
   return result
def getListOfFiles(dirName):
    listOfFile = os.listdir(dirName)
    allFiles = list()
    for entry in listOfFile:
        fullPath = os.path.join(dirName, entry)
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)
                
    return allFiles
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

def listdirs(rootdir):
    dir_list = []
    for path in Path(rootdir).iterdir():
        if path.is_dir():
            print("\n")
            dir_list.append(str(path))
    return dir_list

print("STARTING THE SCANNER")
path = pathlib.Path().resolve()
list_of_all_files = getListOfFiles(str(path)+'\\Package\\')
rootdir = str(path)+'\\Package\\'
LIST_OF_DIRECTORIES =  listdirs(rootdir)
print(LIST_OF_DIRECTORIES)
for l in range (len(LIST_OF_DIRECTORIES)):
    list_of_all_files = getListOfFiles(LIST_OF_DIRECTORIES[l])
    #print(list_of_all_files)
    rule = yara.compile('./yara-rules/rules.yar')
    for i in range(len(list_of_all_files)):
        match = rule.match(list_of_all_files[i])
        if (len(match) >= 1):
            #print(type(match))
            print(colored(('Title: ' + list_of_all_files[i]),'green'))
            print(colored('Rules matched on:[', 'yellow'), end = "")
            #print(len(match["main"]))
            for m in range (len(match["main"])):
                print(colored((str(match["main"][m]["rule"])+ ","), 'yellow'), end = "")
            print("]")
            print((colored(('Malicious file paths:['), 'red')), end = "")
            print(colored(list_of_all_files[i],'red') , end="]")
            print("\n-------------------")
        '''
        else:
            #print('no match')
            #print(res[i])
            #print(list_of_all_files[i])
            #shutil. rmtree(LIST_OF_DIRECTORIES[l])
            print("...")
        '''
    ## Try to remove tree; if failed show an error using try...except on screen
    try: 
        os.remove(LIST_OF_DIRECTORIES[l] + '.tar.gz')
        os.remove(LIST_OF_DIRECTORIES[l] + '.tgz')
        print("removing..." + LIST_OF_DIRECTORIES[l])
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))
print("STOPPING THE SCANNER")

