from fileinput import filename
from selenium import webdriver
from selenium.webdriver.common.by import By
import requests
import wget
import tarfile
from os.path import exists
import time
import requests
import pathlib
import json

with open('config.json') as config_file:
    creds = json.load(config_file)

r = requests.get("https://libraries.io/api/search?q=&sort=created_at&api_key=" + creds['api-key-libraries-io'])
for i in range(len(r.json())):
    package_name = r.json()[i]["name"]
    path = str(pathlib.Path().resolve()) + "\Package\\" 
    to_path = str(pathlib.Path().resolve())
    
    url_download = r.json()[i]["latest_download_url"]
    if (url_download is not None):        
        latest_release_number = r.json()[i]["latest_release_number"]       
        print(latest_release_number)
        print(url_download)
        if (latest_release_number is not None):
            ext = r.json()[i]["latest_download_url"][-4:]
            file_name = package_name + "-" +latest_release_number + ext
            file_name_no_ext = package_name + "-" + latest_release_number
            file_exists = exists(file_name)
            if (file_exists):
                print("file already exists")
            try:
                wget.download(url_download,path)
                time.sleep(3)
            
                if (file_exists):             
                    if ('whl' in file_name):
                        print('Skipped .whl files')
                    elif ('gzip' in file_name):
                        print('Skipped .gzip files')
                    elif ('bzip2' in file_name):
                        print('Skipped .bzip2 files')
                    elif ('lzma' in file_name):
                        print('Skipped .lzma files')
                    else:
                        file = tarfile.open(path + file_name)
                        # extracting file
                        file.extractall(path + str(file_name_no_ext))
                        file.close()
                else:
                    time.sleep(10) 
                    print('UNZIPPING A TAR file AFTER WAITED 10 S')
                    file = tarfile.open(path + file_name)
                    # extracting file
                    file.extractall(path + str(file_name_no_ext))
                    file.close()
            except:
                print("Something wrong... try again later!")
           
        else: 
            print("SKIP... No latest release number")
    else: 
        print("SKIP... No download url")

