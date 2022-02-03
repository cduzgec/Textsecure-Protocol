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

#server's long term key --> decrypt
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

# HERE GENERATE A EPHEMERAL KEY 
sA = Crypto.Random.random.randint(0, n-1)
QA = sA * P

epkey = ECPrivateKey(sA, curve)
ekey = ECPublicKey(Point(QA.x,QA.y, curve))


try:
	#REGISTRATION
	"""
	mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': lkey.W.x, 'LKEY.Y': lkey.W.y}
	print(mes)
	response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json = mes)		
	if((response.ok) == False): raise Exception(response.json())
	print(response.json())

	print("Enter verification code which is sent to you: ")	
	code = int(input())

	mes = {'ID':stuID, 'CODE': code}
	response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json = mes)
	if((response.ok) == False): raise Exception(response.json())
	print(response.json())
	"""	
	#STS PROTOCOL

	mes = {'ID': stuID, 'EKEY.X': ekey.W.x, 'EKEY.Y': ekey.W.y}
	response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
	if((response.ok) == False): raise Exception(response.json())
	res=response.json()
	print("RESPONSE FOR STEP 1: ",res)  

	#calculate T,K,U

	QB = Point(res["SKEY.X"], res["SKEY.Y"], curve) # servers key
	
	# Session Key
	T = sA* QB
	U = str(T.x) + str(T.y) + "BeYourselfNoMatterWhatTheySay" 
	message = (str(U)).encode()
	K = (SHA3_256.new(message).digest()) # bytes
	"""
	print("QB: ", QB)
	print("T: ",T)
	print("U: ",U)
	print("K: ",K)
	"""
	#Sign Message

	W1 = (str(QA.x) + str(QA.y) + str(QB.x) + str(QB.y))
	

	k1 = Crypto.Random.random.randint(2, n-1)
	R1 = k1 * P
	r1 = (R1.x) % n
	message1 = (W1).encode()
	h1 = int.from_bytes(SHA3_256.new(message1+r1.to_bytes((r1.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
	s1 = (sL * h1 + k1) % n
	plaintext = ("s"+ str(s1) + "h" + str(h1)).encode()
	"""
	print("W1: ", W1)
	print("s1: ",s1)
	print("h1: ",h1)
	print("plaintext: ",plaintext)
	"""
	cipher = AES.new(K, AES.MODE_CTR)
	Y1 = cipher.encrypt(plaintext) 
	nonceY1 = cipher.nonce + Y1
	ctext = int.from_bytes(nonceY1, byteorder='big')
	"""
	print("Y1:", Y1)
	print("nonceY1: ",nonceY1)
	print("Int of nonceY1: ",ctext)
	"""
	###Send encrypted-signed keys and retrive server's signed keys
	mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
	response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
	if((response.ok) == False): raise Exception(response.json()) 
	res= response.json() 
	print("RESPONSE FOR STEP 4: ",res)  

	Y2 = res.to_bytes((res.bit_length()+7)//8, 'big')
	#print("Y2: ",Y2)

	#Decrypt 

	cipher = AES.new(K, AES.MODE_CTR, nonce=Y2[0:8])   
	decryptedtext = cipher.decrypt(Y2[8:])
	dtext = decryptedtext.decode('UTF-8')
	print("Decrypted text: ", dtext)

	index_s = dtext.find('s') 
	index_h = dtext.find('h') 
	signs = dtext[index_s+1:index_h]
	sign_s = int(signs)
	signh = dtext[index_h+1:]
	sign_h = int(signh)
	"""
	print("sign_s", sign_s)
	print("sign_h", sign_h)
	"""
	#verify
	V = sign_s * P - sign_h * QSer_long
	u = V.x % n    
	W2 = (str(QB.x) + str(QB.y) + str(QA.x) + str(QA.y))
	
	message2 = (W2).encode()
	sign_h2 = int.from_bytes(SHA3_256.new(message2+u.to_bytes((u.bit_length()+7)//8, byteorder='big')).digest(), byteorder='big')%n
	"""
	print("W2: ", W2)
	print("sign_h2: ", sign_h2)
	"""
	if (sign_h ==  sign_h2):
		print("Accept signature")
		#get a message from server for 
		mes = {'ID': stuID}
		response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
		res= response.json()         
		print("RESPONSE FOR STEP 6:",response.json())

	else:
		print("Reject signature")

	#Decrypt

	W3 = res.to_bytes((res.bit_length()+7)//8, 'big')
	#print("W3: ",W3)

	#Decrypt 

	cipher = AES.new(K, AES.MODE_CTR, nonce=W3[0:8])   
	decryptedtext = cipher.decrypt(W3[8:])
	dtext = decryptedtext.decode('UTF-8')
	print("Decrypted text: ", dtext)


	# find where random number begins and edit this line
	dot = dtext.find(".")
	num = dtext[dot:]
	message3 = dtext[0:dot+2]   
	rand = dtext[dot+1:]
	rand = int(rand)

	print("Message:", message3)
	print("Random number:", rand)

	#Add 1 to random to create the new message and encrypt it

	rando = rand+1
	W4 = (message3+ str(rando)).encode()
	#print("W4: ",W4)

	cipher = AES.new(K, AES.MODE_CTR)
	EW4 = cipher.encrypt(W4) 
	nonceW4 = cipher.nonce + EW4
	ct = int.from_bytes(nonceW4, byteorder='big')
	
	#send the message and get response of the server
	mes = {'ID': stuID, 'ctext': ct}
	response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
	res= response.json()         
	print(response.json())

	success_message = res .to_bytes((res.bit_length()+7)//8, 'big')
	#print("success: ",success_message)

	cipher = AES.new(K, AES.MODE_CTR, nonce=success_message[0:8])   
	decryptedtext = cipher.decrypt(success_message[8:])
	dtext = decryptedtext.decode('UTF-8')
	print("Final text: ", dtext)

except Exception as e:
	print(e)
