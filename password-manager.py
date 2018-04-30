#!/usr/bin/env python3

import argparse
import binascii
import sys
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def main():
    args = parse_args()
    master_password = getpass('Master password: ')

    if len(args) > 0:
        handle_args(args)
    else:
        shell_mode(master_password)


def parse_args():
    parser = get_parser()
    args = parser.parse_args()
    return vars(args)


def parse_command(cmd):
    parser = get_parser()
    split_command = cmd.split(' ')
    args = parser.parse_args(split_command)
    return vars(args)


def get_parser():
    # basic arguments
    parser = argparse.ArgumentParser(prog='Password Manager')
    subparsers = parser.add_subparsers()

    # subcommands
    password_parser = subparsers.add_parser('add')
    add_account_info_to_parser(password_parser)

    generate_parser = subparsers.add_parser('generate')
    add_account_info_to_parser(generate_parser)
    generate_parser.add_argument('-x', '--difficulty', metavar='DIFFICULTY', type=int, required=True,
                                 choices=[1, 2, 3], help='Set password difficulty. ' +
                                                         'Can be 1-[a-zA-Z], 2-[a-zA-Z0-9],3-[a-zA-Z0-9]')
    generate_parser.add_argument('-l', '--length', metavar='LENGTH', type=int, required=True,
                                 help='Set password length.')

    return parser


def add_account_info_to_parser(parser):
    parser.add_argument('DOMAIN')
    parser.add_argument('USERNAME')


def handle_args(args):
    print('There are some args')


def exit(command, m_pass):
    print('Goodbye!')
    sys.exit(0)


def add(command, m_pass):
    print('add called')


def generate(command, m_pass):
    print('generate called')
    create_pass('facebook_user', m_pass)


def get(command, m_pass):
    print('get called')
    read_pass('facebook_user', m_pass)


def print_wrong_command(wrong_command, m_pass):
    print('Unrecognized command: %s' % wrong_command)


actions = {
    'exit': exit,
    'add': add,
    'generate': generate,
    'get': get
}


def shell_mode(master_password):
    print('You entered the shell. Write exit or press ctrl+C to exit!')
    while True:
        command = input()
        actions.get(command, print_wrong_command)(command, master_password)


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


main()
