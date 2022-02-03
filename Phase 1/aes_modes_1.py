from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random

# Begin - Sample usage
# CTR mode
#
print("CTR Mode")
key = Random.new().read(16)
# Encyption
cipher = AES.new(key, AES.MODE_CTR)
ptext = b'sona si latine loqueris'
ctext = cipher.nonce + cipher.encrypt(ptext) 
print("AAAAAAAAAAA", (cipher.nonce), (ctext))
# Decryption
cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
print("BBBBBBBBBB", (cipher.nonce),  (ctext))
dtext = cipher.decrypt(ctext[8:])
print("Decrypted text: ", dtext.decode('UTF-8'))
print("CCCCCCCCCCCC", 	(cipher.nonce),  (ctext))

#  CBC mode
#
print("CBC Mode")
key = Random.new().read(16)
iv = Random.new().read(AES.block_size)
# Encyption
cipher = AES.new(key, AES.MODE_CBC, iv)
ptext = b'sona si latine loqueris'
ctext = iv + cipher.encrypt(pad(ptext, AES.block_size))
# Decryption
cipher = AES.new(key, AES.MODE_CBC, ctext[0:16])
dtext = cipher.decrypt(ctext[16:])
dtext = unpad(dtext, AES.block_size)
print("Decrypted text: ", dtext.decode('UTF-8'))
#
# End - Sample usage

# Begin - Exercise
#
# CTR mode
# Decrypt the ciphertext "ctext" using the secret key "key" and find my credit card number
key = b'\xa0\xf5\xd0>\x11\x9b\xcc\xb3\\G\xd5\xa6\x07\x7f-\xb0'
ctext = b'\t\x1f\xe6\x86\x1d\x9eW[N\xb8\x19C \xb8\xd2I\x86t`m\x1a\xc1v%\xf7J\x88'
#    
# End - Exercise
