#!/usr/bin/python

import hashlib,binascii
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

def generate_key( password,salt, iter):

    #mas konyvatarugyan azt csinaljak , valaszhatunk
    key = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iter))
    key2=binascii.hexlify(PBKDF2(password,salt))

    return key2

def read_pass(source):

    with open('passwords/'+source, 'r') as file:
        salt=file.readline().rstrip()
        e_pass=file.readline()

    print(salt+' '+e_pass)

    return e_pass, salt


def write_pass(source,salt,e_pass):

    with open('passwords/'+source, 'w') as file:
        file.writelines(salt)
        file.writelines(e_pass)



    return e_pass, salt


def encrypt(k,p):

    cipher = AES.new(k, AES.MODE_EAX)
    nonce = cipher.nonce

    #return ciphertext, tag,nonce
    ciphertext,tag=cipher.encrypt_and_digest(p)
    return  (ciphertext,tag,nonce)


def decrypt(k,ciphertext,nonce,tag):

    cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)

        return plaintext

    except ValueError:
        print("Key incorrect or message corrupted")



read_pass('master_password')

k=generate_key("password",'salt',1000)

p=b'googlepassword'


#TODO tag nonce mire is valo, ki lehet e irni csak ugy
(ciphertext, tag, nonce) = encrypt(k,p)

print('cipherd'+str(ciphertext))

password=decrypt(k,ciphertext,nonce,tag)

print(password)

    
#m_pass = input('Master password: ')
#asd=hashlib.pbkdf2_hmac('sha256', m_pass,b'pass',b'salt',1000)

#validate_password(m_pass)

'''
def validate_password(m_pass):


	real_m_pass_file = open('passwords/master_password', 'r')
	real_m_pass = real_m_pass_file.readline()
	real_m_pass_file.close()
	asd=hashlib.pbkdf2_hmac('sha256', m_pass, b'pass', b'salt', 1000).decode()

	if m_pass == real_m_pass:
		print('Correct password!')
		exit(0)

	print('Incorrect password')
'''
