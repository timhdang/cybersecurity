from selenium import webdriver
from selenium.webdriver.common.by import By
import wget
import tarfile
from os.path import exists
import time
import scannerX


def main():
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.get("https://pypi.org/search/?q=a&o=-created&c=Programming+Language+%3A%3A+JavaScript")
    driver.implicitly_wait(3)
    package = driver.find_elements(By.CSS_SELECTOR, 'ul.unstyled>li:nth-child(n)>a')
    for i in range(2):
        print(package[i].get_attribute('href'))
        print("Download files of project" + package[i].text)
        driver2 = webdriver.Chrome(options=options)
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
                elif ('gzip' in file_name):
                    print('Skipped .gzip files')
                elif ('bzip2' in file_name):
                    print('Skipped .bzip2 files')
                elif ('lzma' in file_name):
                    print('Skipped .lzma files')
                else:
                    print("path + filename=" + path + file_name)
                    print('UNZIPPING A TAR file')
                    file = tarfile.open(path + file_name)
                    # extracting file
                    
                    file.extractall(path)
                    file.close()
            else:
                time.sleep(10)
                print("path + filename=" + path + file_name)
                print('UNZIPPING A TAR file AFTER WAITED 10 S')              
                file = tarfile.open(path + file_name)
                # extracting file
                file.extractall(path)
                file.close()


if __name__ == '__main__':
    main() 
    scannerX.main()
        