import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import requests
from Crypto.Cipher import AES
from Crypto import Random
import Crypto.Random.random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib, hmac, binascii
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  23928 
stuID_B = 24773 



#create a long term key
curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

sL = 69361608709905046101823262541775249737368519378808050119901286618529808136530 
#sL =Crypto.Random.random.randint(2, n-1)   --> only for the registration

QL = sL * P   
private_key = ECPrivateKey(sL, curve)
lkey = ECPublicKey(Point(QL.x,QL.y, curve))  # Public key

k = Crypto.Random.random.randint(2, n-1)
R = k * P
r = (R.x) % n


message = (str(stuID_B)).encode()
h = int.from_bytes(SHA3_256.new(message+r.to_bytes((r.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
s = (sL * h + k) % n




####Register Long Term Key

#s, h = SignGen(str(stuID).encode(), curve, sL)#sCli_long
mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': lkey.W.x, 'LKEY.Y': lkey.W.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json())
# code = 319170
code = int(input())

mes = {'ID':stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())


#Check Status
mes = {'ID_A':stuID, 'H': h, 'S': s}
response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)
print("Status ", response.json())

array_SA = []
array_QA = []
array_QB =[]
array_MSG =[]

# HERE GENERATE A EPHEMERAL KEY 
for i in range (0,10):
    sA = Crypto.Random.random.randint(0, n-1)
    QA = sA * P
    epkey = ECPrivateKey(sL, curve)
    ekey = ECPublicKey(Point(QA.x,QA.y, curve))

    array_SA.append(sA)
    array_QA.append(QA)

    k1 = Crypto.Random.random.randint(2, n-1)
    R1 = k1 * P
    r1 = (R1.x) % n

    message = (str(QA.x) + str(QA.y)).encode()
    h1 = int.from_bytes(SHA3_256.new(message+r1.to_bytes((r1.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
    s1 = (sL * h1 + k1) % n

    #Send Ephemeral keys
    mes = {'ID': stuID, 'KEYID': i , 'QAI.X': ekey.W.x, 'QAI.Y': ekey.W.y, 'Si': s1, 'Hi': h1}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
    print(response.json())



for i in range(0,10):
    ### Get key of the Student B
    mes = {'ID_A': stuID, 'ID_B':stuID_B, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json = mes)
    res = response.json()
    print(res)
    QB_x = res["QBJ.x"]
    QB_y = res["QBJ.y"]
    #QB = Point(res["QBJ.X"], res["QBJ.Y"], curve)
    QB = Point(QB_x, QB_y, curve)
    array_QB.append(QB)


    T = array_SA[i] * QB
    U = (str(T.x)+str(T.y) + "NoNeedToRunAndHide").encode()
    K_ENC = (SHA3_256.new(U).digest()) 
    K_MAC = (SHA3_256.new(K_ENC).digest())  

    #MSG = "Random Message"
    #cipher = AES.new(K_ENC, AES.MODE_CTR)
    #ctext = int.from_bytes(cipher.nonce+cipher.encrypt(MSG), byteorder='big')

    #h = HMAC.new(K_MAC, ctext, digestmod=SHA256)
    #h.update(ctext)
    #msg = str(ctext) + str(h)
    #msg = int(msg)

### Send message to student B
mes = {'ID_A': stuID, 'ID_B':stuID_B, 'I': i, 'J':j, 'MSG': msg}
response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json = mes)
print(response.json())


## Get your message
mes = {'ID_A': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json = mes)
print(response.json())
if(response.ok):
    # decrypt
    cipher = AES.new(K_ENC, AES.MODE_CTR, nonce=ciphertext[0:8])   
    decryptedtext = cipher.decrypt(ciphertext[8:-32])
    dtext = decryptedtext.decode("latin1")
    print("Decrypted text: ", dtext)
    
"""
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
"""

