#!/usr/bin/python

import hashlib,binascii
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

def generate_key( password,salt, iter):

    key2=binascii.hexlify(PBKDF2(password,salt))

    return key2

def read_file(file):

    with open('passwords/'+file, 'r') as f:
        salt=f.readline().rstrip()
        tag = f.readline().rstrip()
        nonce = f.readline().rstrip()
        e_pass=f.readline()
    #print('Read\nsalt: ' + salt + '\ntag: ' + str(tag) + '\nnon: ' + str(nonce) + '\nepass: ' + str(e_pass))
    return e_pass,salt,tag,(nonce)


def write_file(file,salt,tag,nonce,e_pass):

    #print('Write\nsalt: '+salt+'\ntag: '+str(tag)+'\nnon: '+str(nonce)+'\nepass: '+str(e_pass))
    with open('passwords/'+file, 'w') as f:
        f.write(salt)
        f.write('\n')
        f.write((tag).decode('unicode-escape'))
        f.write('\n')
        f.write((nonce).decode('unicode-escape'))
        f.write('\n')
        f.write((e_pass).decode('unicode-escape'))

    return e_pass, salt

def generate_pass(a,A,num,spec,lenght):

    #TODO generate password with parameters bool a-z,bool A-Z,bool number,bool spec,int length

    return "password"


def encrypt(key,password):

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext,tag=cipher.encrypt_and_digest(password)

    return  (tag,nonce,ciphertext)


def decrypt(k,ciphertext,nonce,tag):

    nonce=nonce.encode('ISO-8859-1')
    tag = bytes(tag, 'ISO-8859-1')
    ciphertext=bytes(ciphertext, 'ISO-8859-1')



    cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)

        return plaintext

    except ValueError:
        print("Key incorrect or message corrupted")



def create_pass(file, m_pass):

    salt='randomsalt'
    iter=1000
    key=generate_key(m_pass,salt,iter)

    password=generate_pass(True,False,False,False,8)
    tag,nonce,e_pass=encrypt(key, password.encode())
    write_file(file, salt, tag,nonce,e_pass )

    print('Password Saved!')


def read_pass(file,m_pass):
    e_pass, salt, tag, nonce=read_file(file)
    key=generate_key(m_pass,salt,tag)

    password=decrypt(key,e_pass,nonce,tag)

    print(password)




create_pass('facebook_user','master')

read_pass('facebook_user','master')
