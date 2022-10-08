from logging import root
import os
import yara
from os.path import exists
import shutil
import glob
from termcolor import colored
import pathlib
from pathlib import Path
import datetime
import send_mail_util
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

'''
def main():
    print("STARTING THE SCANNER")
    dir_path = r'**/setup.py'
    match_dir = glob.glob(dir_path)
    rule = yara.compile('./yara-rules/rules.yar')
    time_stamp = datetime.today().strftime('%Y%m%d_%H%M%S')
    malware_log = open(time_stamp + ".txt","w+")
    for i in range(len(match_dir)):
        match = rule.match(match_dir[i])
        if (len(match) >= 1):
            print("Title: " + match_dir[i].replace("\setup.py",""))
            print("Rules matched on:[", end = "")
            for m in range (len(match["main"])):
                print(str(match["main"][m]["rule"])+ ",", end = "")
            print("]")
            print("Malicious file paths:[", end = "")
            print(match_dir[i], end="]")
            print("\n-------------------")
        else:
            print('no match')
            print(match_dir[i].replace('\\setup.py',''))
            shutil. rmtree(match_dir[i].replace('\\setup.py',''))   #delete the entire directory after analyzed.
    print("STOPPING THE SCANNER")
'''
def listdirs(rootdir):
    dir_list = []
    for path in Path(rootdir).iterdir():
        if path.is_dir():
            print("\n")
            dir_list.append(str(path))
    return dir_list

def main():
    print("STARTING THE SCANNER")
    time_stamp = datetime.date.today().strftime('%Y%m%d')
    log_name = time_stamp + ".txt"
    malware_log = open(log_name,"w+")
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
            try: 
                match = rule.match(list_of_all_files[i])
                if (len(match) >= 1):
                    #print(type(match))
                    with open(log_name, 'a') as f:
                        f.write('Infected files: ' + list_of_all_files[i])
                        f.write('\n')
                        f.close()
                    print(colored(('Title: ' + list_of_all_files[i]),'green'))
                    print(colored('Rules matched on:[', 'yellow'), end = "")
                    #print(len(match["main"]))
                    for m in range (len(match["main"])):
                        print(colored((str(match["main"][m]["rule"])+ ","), 'yellow'), end = "")
                    print("]")
                    print((colored(('Malicious file paths:['), 'red')), end = "")
                    print(colored(list_of_all_files[i],'red') , end="]")
                    print("\n-------------------")
                    with open(log_name, 'a') as f:
                        f.write('Infected rules:')
                        for m in range (len(match["main"])):
                            f.write(str(match["main"][m]["rule"]))
                        f.write('\n--------------\n')
                        f.close()
                else:
                    print("...")
            except: 
                print("YARA exception met!!")
        print("Done with " + LIST_OF_DIRECTORIES[l])    
        ## Try to remove tree; if failed show an error using try...except on screen
        try: 
            shutil.rmtree(LIST_OF_DIRECTORIES[l])
            print("removing..." + LIST_OF_DIRECTORIES[l])
        except OSError as e:
            print ("Error: %s - %s." % (e.filename, e.strerror))   #
    print("STOPPING THE SCANNER")
    send_mail_util.main()

if __name__ == '__main__':
    main() 

