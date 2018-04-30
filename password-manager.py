#!/usr/bin/env python3

from getpass import getpass
import argparse, sys
import hashlib, binascii
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES


# def get_parser():
# 	# basic arguments
# 	parser = argparse.ArgumentParser(prog='Password Manager')
# 	parser.add_argument('domain', nargs='?')
# 	parser.add_argument('username', nargs='?')
# 	subparsers = parser.add_subparsers()

# 	# subcommands
# 	password_parser = subparsers.add_parser('add-pass')
# 	password_parser.add_argument('-p', '-pass', metavar='PASSWORD', help='Use predefined password.',
# 		required=True)

# 	generate_parser = subparsers.add_parser('generate-pass')
# 	generate_parser.add_argument('-x', metavar='DIFFICULTY', type=int, help='Set password difficulty. ' + 
# 		'Can be 1-[a-zA-Z], 2-[a-zA-Z0-9],3-[a-zA-Z0-9]+special characters', required=True)
# 	generate_parser.add_argument('-l', metavar='LENGTH', help='Set password length.', required=True)

# 	return parser

def generate_key(password, salt, iter):
    key2 = binascii.hexlify(PBKDF2(password, salt))

    return key2


def read_file(file):
    with open('passwords/' + file, 'rb') as f:
        salt = f.readline().rstrip()
        tag = f.readline().rstrip()
        nonce = f.readline().rstrip()
        e_pass = f.readline()
    # print('Read\nsalt: ' + salt + '\ntag: ' + str(tag) + '\nnon: ' + str(nonce) + '\nepass: ' + str(e_pass))
    return e_pass, salt, tag, (nonce)


def write_file(file, salt, tag, nonce, e_pass):
    # print('Write\nsalt: '+salt+'\ntag: '+str(tag)+'\nnon: '+str(nonce)+'\nepass: '+str(e_pass))
    with open('passwords/' + file, 'wb') as f:
        f.write(salt.encode())
        f.write('\n'.encode())
        print((tag).decode('cp437'))
        f.write((tag))
        f.write('\n'.encode())
        f.write((nonce))
        f.write('\n'.encode())
        f.write((e_pass))

    return e_pass, salt


def generate_pass(a, A, num, spec, length):
    # TODO generate password with parameters bool a-z,bool A-Z,bool number,bool spec,int length

    return "password"


def encrypt(key, password):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password)

    return (tag, nonce, ciphertext)


def decrypt(k, ciphertext, nonce, tag):
    '''
    nonce=nonce.encode('ISO-8859-1')
    tag = bytes(tag, 'ISO-8859-1')
    ciphertext=bytes(ciphertext, 'ISO-8859-1')
    '''

    cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)

        return plaintext

    except ValueError:
        print("Key incorrect or message corrupted")


def create_pass(file, m_pass):
    salt = 'randomsalt'
    iter = 1000
    key = generate_key(m_pass, salt, iter)

    password = generate_pass(True, False, False, False, 8)
    tag, nonce, e_pass = encrypt(key, password.encode())
    write_file(file, salt, tag, nonce, e_pass)

    print('Password Saved!')


def read_pass(file, m_pass):
    e_pass, salt, tag, nonce = read_file(file)
    key = generate_key(m_pass, salt, tag)

    password = decrypt(key, e_pass, nonce, tag)

    print(password)


def validate_password(m_pass):
    real_m_pass_file = open('passwords/master_password', 'r')
    real_m_pass = real_m_pass_file.readline()
    real_m_pass_file.close()
    if m_pass == real_m_pass:
        print('Correct password!')
        return
    print('Incorrect password!')
    exit(0)


def exit(command, m_pass):
    print('Goodbye!')
    sys.exit(0)


def add(command, m_pass):
    print('add called')
    create_pass('facebook_user', m_pass)


def get(command, m_pass):
    print('get called')
    read_pass('facebook_user', m_pass)


def print_wrong_command(wrong_command):
    print('Unrecognized command: %s' % wrong_command)


actions = {
    'exit': exit,
    'add': add,
    'get': get
}

m_pass = getpass('Master password: ')
print('You entered the shell. Write exit or press ctrl+C to exit!')
while True:
    command = input()
    actions.get(command, print_wrong_command)(command, m_pass)
