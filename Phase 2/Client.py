import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
import Crypto.Random.random
from Crypto import Random
import Crypto.Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 23928 


#create a long term key

# verification code : 167248
#HERE CREATE A LONG TERM KEY

curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

sL = 69361608709905046101823262541775249737368519378808050119901286618529808136530
#sL =Crypto.Random.random.randint(2, n-1)   #--> only for the registration

QL = sL * P   
private_key = ECPrivateKey(sL, curve)
lkey = ECPublicKey(Point(QL.x,QL.y, curve))  # Public key
"""
print('sL: ', sL)
print('QL: ', QL)
print("private: ", private_key)
print("public key: ", lkey)
"""
k = Crypto.Random.random.randint(2, n-1)
R = k * P
r = (R.x) % n

# encode them seperately
#send everything as integer
message = (str(stuID)).encode()
h = int.from_bytes(SHA3_256.new(message+r.to_bytes((r.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
s = (sL * h + k) % n


#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)


####Register Long Term Key
mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': lkey.W.x, 'LKEY.Y': lkey.W.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json())
code = input()

mes = {'ID':stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())



#send ephemeral key
mes = {'ID': stuID, 'KEYID': i , 'QAI.X': ekey.x, 'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
print(response.json())




#Receiving Messages
mes = {'ID_A': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
print(response.json())


#decrypt messages

#send decrypted messages to server
mes = {'ID_A': stuID, 'DECMSG': h}
response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)


###delete ephemeral keys
mes = {'ID': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)



###########DELETE LONG TERM KEY
# If you lost your long term key, you can reset it yourself with below code.

# First you need to send a request to delete it. 
mes = {'ID': stuID}
response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)

#Then server will send a verification code to your email. 
# Send this code to server using below code
mes = {'ID': stuID, 'CODE': code}
response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)

#Now your long term key is deleted. You can register again. 

