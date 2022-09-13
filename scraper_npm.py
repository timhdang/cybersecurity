from fileinput import filename
from selenium import webdriver
from selenium.webdriver.common.by import By
import os
import urllib.request
import requests
import wget
import tarfile
from os.path import exists
import time
import scannerX
import requests
import shutil

r = requests.get("https://libraries.io/api/search?q=&sort=created_at&api_key=b807cdbb55b5c20c7fac91189c8191f4")
print(len(r.json()))

for i in range(5):
    title = r.json()[i]["name"]
    #print(title)
    url_download = ""
    try: 
        url_download = r.json()[i]["latest_download_url"]
    except: 
        url_download = ""
        print("THIS REPO HAS NO DIRECT DOWNLOAD LINK")
    ext = ""
    try:
        ext = url_download[-4:]
    except: 
        ext = ""
    path = "C:/Users/17142/Desktop/Cyber/Package/" + str(title.split('/')[-1]) + str(ext)
    #print(url_download)
    print(path)
    print("download url = " + str(url_download))
    if (r.json()[i]["latest_download_url"] == "None"):
        print("SKIP... No download url")
    else:
        if (ext == ".tgz"):
            full_title = title + ".tgz"
        elif (ext == "r.gz"):
            full_title = title + ".tar.gz"
        else: 
            full_title = title + ext
        file_exists = exists(full_title)
        if (file_exists):
            print("file already exists")
        else:
            try:
                wget.download(url_download,path)
                # open file
                if (file_exists):
                    if ('whl' in title):
                        print('Skipped .whl files')
                    elif ('gzip' in title):
                        print('Skipped .gzip files')
                    elif ('bzip2' in title):
                        print('Skipped .bzip2 files')
                    elif ('lzma' in title):
                        print('Skipped .lzma files')
                    else:
                        print('UNZIPPING A TAR file')
                        if (ext == ".tgz"):
                            path = "C:/Users/17142/Desktop/Cyber/"
                            to_path = "C:/Users/17142/Desktop/Cyber/"
                            file = tarfile.open(path + title+ ".tgz")
                            # extracting file
                            print("start extracting path 1")
                            file.extractall(to_path + title)
                            file.close()
                        elif (ext == "r.gz"):
                            file = tarfile.open(path +  title+ ".tar.gz")
                            # extracting file
                            file.extractall(path + title)
                            file.close()
                        else: 
                            print("CANNOT UNZIP AT THE MOMENT")
                else:
                    time.sleep(10)
                    print('UNZIPPING A TAR file AFTER WAITED 10 S')
                    path = "C:/Users/17142/Desktop/Cyber/Package/"
                    to_path = "C:/Users/17142/Desktop/Cyber/"
                    if (ext == ".tgz"):         
                        file = tarfile.open(path + title+ ".tgz")
                        # extracting file
                        #print(path+title)
                        print("start extracting path 2")
                        file.extractall(path + title)
                        file.close()
                    elif (ext == "r.gz"):
                        file = tarfile.open(path +  title+ ".tar.gz")
                        # extracting file
                        #print(path+title)
                        print("start extracting path 3")
                        file.extractall(to_path + title)
                        file.close()
                    else: 
                        print("CANNOT UNZIP AT THE MOMENT")
            except:
                print("ERROR 101- download links not exists.")
    ## Try to remove tree; if failed show an error using try...except on screen
    try: 
        os.remove(path + title + ext)
        print("removing..." + str(path + title + ext))
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))
'''
package = driver.find_elements(By.CSS_SELECTOR, 'ul.unstyled>li:nth-child(n)>a')
for i in range(50):
    print(package[i].get_attribute('href'))
    print("Download files of project" + package[i].text)
    driver2 = webdriver.Chrome()
    print(package[i].get_attribute('href')+'#files')
    driver2.get(package[i].get_attribute('href')+'#files')
    url_download =  driver2.find_element(By.CSS_SELECTOR,'#files > div:nth-child(4) > div.card.file__card > a:nth-child(1)')
    print("url=" + url_download.get_attribute('href'))
    #print(url_download.text)
    #url_download.click()
    path = "C:/Users/17142/Desktop/Cyber/Package"
    file_name = url_download.text
    print('file_name=' + file_name)
    file_exists = exists(file_name)
    if (file_exists):
        print("file already exists")
    else:
        wget.download(url_download.get_attribute('href'),path)
        driver.implicitly_wait(3)
        print('filename=' + file_name)
        # open file
        if (file_exists):
            if ('whl' in file_name):
                print('Skipped .whl files')
            else:
                print('UNZIPPING A TAR file')
                file = tarfile.open(file_name)
                # extracting file
                file.extractall(path)
                file.close()
        else:
            time.sleep(10)
            print('UNZIPPING A TAR file AFTER WAITED 10 S')
            file = tarfile.open(file_name)
            # extracting file
            file.extractall(path)
            file.close()


if __name__ == '__main__':
    # service.py executed as script
    # do something
    if ('whl' in file_name):
                print('Skipped .whl files in MAIN')
    else:
        scannerX.run_scannerX(file_name.replace('.tar.gz',''))
'''