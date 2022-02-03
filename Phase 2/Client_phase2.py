import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA256
import requests
from Crypto.Cipher import AES
import Crypto.Random.random
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from ecpy.keys import ECPublicKey, ECPrivateKey
from Crypto.Hash import HMAC, SHA256
from ecpy.ecdsa import ECDSA
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 23928

#HERE CREATE A LONG TERM KEY

curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

sL = 69361608709905046101823262541775249737368519378808050119901286618529808136530
#sL =Crypto.Random.random.randint(2, n-1)   --> only for the registration

QL = sL * P   
private_key = ECPrivateKey(sL, curve)
lkey = ECPublicKey(Point(QL.x,QL.y, curve))  # Public key
'''
print('sL: ', sL)
print('QL: ', QL)
print("private: ", private_key)
print("public key: ", lkey)
'''
k = Crypto.Random.random.randint(2, n-1)
R = k * P
r = (R.x) % n
message = (str(stuID)).encode()
h = int.from_bytes(SHA3_256.new(message+r.to_bytes((r.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
s = (sL * h + k) % n
 
#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

"""
####Register Long Term Key
mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': lkey.W.x, 'LKEY.Y': lkey.W.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json(), "Please put your code")
code = input()

mes = {'ID':stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())
"""
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

    #send ephemeral key
    print("Send ephemeral key for key id: ", i)
    mes = {'ID': stuID, 'KEYID': i , 'QAI.X': ekey.W.x, 'QAI.Y': ekey.W.y, 'Si': s1, 'Hi': h1}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
    print(response.json())

#print("QA ARRAY: ",array_QA)
#print("SA ARRAY: ",array_SA)

for i in range (0,10):
    #print("RECEIVE MESSSAGE")
    #Receiving Messages
    mes = {'ID_A': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    res = response.json()
    
    QB = Point(res["QBJ.X"], res["QBJ.Y"], curve) # servers key
    array_QB.append(QB)
    array_MSG.append(res["MSG"])

    T = array_SA[i] * QB
    U = (str(T.x)+str(T.y) + "NoNeedToRunAndHide").encode()
    K_ENC = (SHA3_256.new(U).digest())  # encode this if it doesnt work
    K_MAC = (SHA3_256.new(K_ENC).digest())  
    #print("K_ENC: ", K_ENC, "K_MAC: ", K_MAC )

    #decrypt messages
    ciphertext = res["MSG"].to_bytes((res["MSG"].bit_length()+7)//8, 'big')


    """
    mac = int( str(res["MSG"])[-32:])
    print("mac",mac)

    r = str(res["MSG"])[0:-32]
    re = int(r)
    cipher = re.to_bytes((re.bit_length()+7)//8, 'big')
    
    h = HMAC.new(K_MAC, cipher, digestmod=SHA256)
    h.update(cipher)
    try:
        h.hexverify(mac)
        print("The message '%s' is authentic" % cipher)
    except ValueError:
        print("The message or the key is wrong")
    
    """

    cipher = AES.new(K_ENC, AES.MODE_CTR, nonce=ciphertext[0:8])   
    decryptedtext = cipher.decrypt(ciphertext[8:-32])
    dtext = decryptedtext.decode("latin1")
    print("Decrypted text: ", dtext)

  
    #print("SEND DECRYPTED MESSSAGE")
    #send decrypted messages to server
    mes = {'ID_A': stuID, 'DECMSG': dtext}
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())


"""
# you must sign your ID using your long-term private key

###delete ephemeral keys
mes = {'ID': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
print(response.json())


###########DELETE LONG TERM KEY
# If you lost your long term key, you can reset it yourself with below code.




# First you need to send a request to delete it. 
mes = {'ID': stuID}
response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)
print(response.json())
#Then server will send a verification code to your email. 
# Send this code to server using below code
mes = {'ID': stuID, 'CODE' :code}
response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)
print(response.json())
#Now your long term key is deleted. You can register again. 
"""
