import re
import os
import pandas
import argparse
import itertools
import csv

import pandas as pd

import numpy as np
import matplotlib.pyplot as plt

from os.path import isfile
from os import listdir

from collections import OrderedDict
from operator import itemgetter

import requests
from bs4 import BeautifulSoup 

parser = argparse.ArgumentParser()
parser.add_argument('--file_path',type=str,default = "/",help='File path to parse.')
parser.add_argument('--ham',type=bool,default = "False" ,help='Only preprocess Ham.')
parser.add_argument('--spam',type=bool,default = "False" ,help='Only preprocess Spam.')
args = parser.parse_args()


spam_dict = {'update' : 0,'confirm' : 0,'user' : 1,'customer' : 1,'client' : 1,'suspend' : 2,'restrict' : 2,'hold' : 2,
            'verify' : 3,'account' : 3,'notif' : 3,'login' : 4,'username' : 4,'password' : 4,'click' : 4,'log' : 4,
            'ssn' : 5,'social security' : 5,'secur' : 5,'inconvinien' : 5}

def spam_occurence(file_text):
    spam_count = [0,0,0,0,0,0]
    for key,value in spam_dict.items():
        pattern = re.compile(key)
        matches = pattern.findall(file_text)
        spam_count[value] += len(matches)
    return spam_count


def dot_count(url):
    domain = url.split("//www.")[-1].split("/")[0].split('?')[0]
    if(domain == 'http:' or domain == 'https:'):
        domain = url.split("//")[-1].split("/")[0].split('?')[0]
    domain_list = domain.split('.')
    if(len(domain_list) > 4):
        return 1
    else:
        return 0

def get_domain(url):
    domain = url.split("//www.")[-1].split("/")[0].split('?')[0]
    if(domain == 'http:' or domain == 'https:'):
        domain = url.split("//")[-1].split("/")[0].split('?')[0]
    domain_list = domain.split('.')
    if(len(domain_list) > 2):
        domain = domain_list[len(domain_list)-2] +'.'+domain_list[len(domain_list)-1]

    return domain


URL_REGEX = re.compile(
    u"^"
    # protocol identifier
    u"(?:(?:https?|ftp)://)"
    # user:pass authentication
    u"(?:\S+(?::\S*)?@)?"
    u"(?:"
    # IP address exclusion
    # private & local networks
    u"(?!(?:10|127)(?:\.\d{1,3}){3})"
    u"(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})"
    u"(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})"
    # IP address dotted notation octets
    # excludes loopback network 0.0.0.0
    # excludes reserved space >= 224.0.0.0
    # excludes network & broadcast addresses
    # (first & last IP address of each class)
    u"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
    u"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}"
    u"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"
    u"|"
    # host name
    u"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)"
    # domain name
    u"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*"
    # TLD identifier
    u"(?:\.(?:[a-z\u00a1-\uffff]{2,}))"
    u")"
    # port number
    u"(?::\d{2,5})?"
    # resource path
    u"(?:/\S*)?"
    u"$"
    , re.UNICODE)


def my_func(file_path,idx):
    text = open(file_path,'r',encoding='utf-8', errors='ignore').read().replace('\n','')

    re_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    re_url = re.compile('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    urls = re.findall(re_url, text)

    #3.2.1 ip value detection
    ip=0
    for url in urls:
        if len(re.findall(re_ip,url)) is not 0:
            ip=1

    #3.2.2 href
    soup = BeautifulSoup(text,'lxml')
    links = soup.find_all("a")
    href_Check_value =0
    for link in links:
        if type(link.get("href")) is str:
            if len(re.findall(URL_REGEX,link.get("href"))) != 0:
                if(len(re.findall(URL_REGEX,link.text))) !=0:
                    link1 = re.findall(URL_REGEX,link.get("href"));
                    link2 = re.findall(URL_REGEX,link.text);
                    if( (get_domain(link1[0])).lower() != (get_domain(link2[0])).lower() ):
                        href_Check_value =1
                        break

    #3.2.3 linkcheck
    linkclickcheck=0
    linktexts = ['Click', 'Here', 'Login', 'Update', 'Link']

    for link in links:
        if type(link.text) is str:
            for linktext in linktexts:
                pattern = re.compile(linktext)
                matches = pattern.findall(link.text)
                if len(matches) !=0:
                    linkclickcheck=1
                    break

    #3.2.4 dots in domain name
    dotcount=0
    for url in urls:
        # domain = get_domain(url)
        if (dot_count(url)):
            dotcount=1
            break

    #3.2.5 mime
    mime=0
    if "Content-Type: text/html" in text:
        mime=1

    #3.2.6 Javascript
    javapresent = 0
    links = soup.find_all("script")
    if(len(links)>0):
        javapresent = 1

    #3.2.7  linksnumber
    linknumber = len(urls)

    #3.2.8 unique domains
    domain_set = set()
    for url in urls:
        domain_set.add(get_domain(url))
    uniquedomain = len(domain_set)

    #3.2.9 Body
    bodyvalue = 0
    if(uniquedomain>1):
        bodyvalue =1

    #3.2.10 Word List Features
    wordlist = spam_occurence(text)

    retrow = [ip, href_Check_value, linkclickcheck, dotcount, mime, javapresent, linknumber, uniquedomain, bodyvalue]
    retrow+=(wordlist)
    retrow.append(idx)

    return retrow

def main():

    if(os.path.exists(args.file_path)):

        if(args.ham):
            ham_path = args.file_path + "ham"
            ham_list = []
            if os.path.isdir(ham_path):
                print("Preprocessing Ham folder.")
                for (dirpath, dirnames, filenames) in os.walk(ham_path):
                    for dirr in dirnames:
                        for (path,dirr,files) in os.walk(os.path.join(ham_path,dirr)):
                            for f in files:
                                if f[:5]!="0000." and f!='cmds':
                                    ham_list.append(my_func(path+'/'+f,0))
                                # else:
                                #     print("oo: " + path+'/'+f)

                print("Finished preprocessing Ham folder.")
            else:
                print("Ham folder does not exist.")
                raise SystemExit
            my_df = pd.DataFrame(ham_list)
            my_df.to_csv('ham.csv', index=False, header=False)


        if(args.spam):
            spam_path = args.file_path + "spam"
            spam_list = []
            if os.path.isdir(spam_path):
                print("Preprocessing Spam folder.")
                for (dirpath, dirnames, filenames) in os.walk(spam_path):
                    for dirr in dirnames:
                        for (path,dirr,files) in os.walk(os.path.join(spam_path,dirr)):
                            for f in files:
                                if f[:5] !="0000." and f!='cmds' :
                                    spam_list.append(my_func(path+'/'+f,1))
                                # else:
                                #     print("oo"+ path+'/'+f)
                print("Finished preprocessing Spam folder.")

            else:
                print("Spam folder does not exist.")
                raise SystemExit
            my_df = pd.DataFrame(spam_list)
            my_df.to_csv('spam.csv', index=False, header=False)

    else:
        print("Invalid System Path.")
        raise SystemExit

from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix

def model():
    ham_list = pd.read_csv('ham.csv', header =None )
    spam_list = pd.read_csv('spam.csv', header = None)
    data = pd.concat([ham_list,spam_list], axis=0)
    print("Ham, Spam, Data: ",ham_list.shape, spam_list.shape, data.shape)

    data = shuffle(data)
    X = data.iloc[ :,:-1]
    Y = data.iloc[ :,-1 ]
    
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.15, shuffle = True)
    rf = RandomForestClassifier(n_estimators=100, criterion='entropy', max_features=8, bootstrap=True)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    y_pred = pd.DataFrame(y_pred)

    print("Precision, recall, fscore, support: ",precision_recall_fscore_support(y_test, y_pred, average='binary'))
    print("Accuracy: ",accuracy_score(y_test, y_pred))
    CM = confusion_matrix(y_test, y_pred)
    TN = CM[0][0]
    FN = CM[1][0]
    TP = CM[1][1]
    FP = CM[0][1]

    print("TN, FN: ", TN, FN)
    print("TP, FP: ", TP, FP)



if __name__ == '__main__':
    main()
    model()




