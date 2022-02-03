import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib, hmac, binascii
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  12345  
stuID_B = 13579

#create a long term key

####Register Long Term Key

s, h = SignGen(str(stuID).encode(), curve, sCli_long)
mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': QCli_long.x, 'LKEY.Y': QCli_long.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json())

code = int(input())

mes = {'ID':18007, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())


#Check Status
mes = {'ID_A':18007, 'H': h, 'S': s}
response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)
print("Status ", response.json())


#Send Ephemeral keys
mes = {'ID': stuID, 'KEYID': i , 'QAI.X': ekey.x, 'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
print(response.json())




### Get key of the Student B
mes = {'ID_A': stuID, 'ID_B':stuID_B, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json = mes)
res = response.json()
print(res)


### Send message to student B
mes = {'ID_A': stuID, 'ID_B':stuID_B, 'I': i, 'J':j, 'MSG': msg}
response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json = mes)
print(response.json())


## Get your message
mes = {'ID_A': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json = mes)
print(response.json())
if(response.ok): ## Decrypt message
    

#####Reset Ephemeral Keys
s, h = SignGen("18007".encode(), curve, sCli_long)
mes = {'ID': stuID, 'S': s, 'H': h}
print(mes)
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
print(response.json())


#####Reset Long Term Key
mes = {'ID': stuID}
response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)
print(response.json())
code = int(input())

mes = {'ID': stuID ,'CODE': code}
response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)
print(response.json())

