from Crypto.Cipher import AES
from Crypto.Random.random import choice
from getpass import getpass
from abc import ABC, abstractmethod
from shutil import rmtree
from itertools import chain
import os
import crypt

from cryptotools.common import AccountHandler, generate_key


class Writer(ABC, AccountHandler):
    def __init__(self, domain, username):
        super().__init__(domain, username)
        self.salt = crypt.mksalt(crypt.METHOD_SHA512)

    def write_pass(self, m_pass):
        password = self._get_password()
        tag, nonce, e_pass = self.__get_encrypted_message(password, m_pass)
        try:
            self.__write_file(self.file, tag, nonce, e_pass)
        except IOError:
            print('Failed to save password. Rolling back...')
            return

        print('Password Saved!')

    def __get_encrypted_message(self, message, m_pass):
        iter = 1000
        key = generate_key(m_pass, self.salt, iter)

        return self.__encrypt(key, message.encode())

    @staticmethod
    def __encrypt(key, message):
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message)

        return tag, nonce, ciphertext

    def __write_file(self, file, tag, nonce, e_message):
        # print('Write\nsalt: '+salt+'\ntag: '+str(tag)+'\nnon: '+str(nonce)+'\nepass: '+str(e_pass))
        with open('passwords/' + file, 'wb') as f:
            f.write(self.salt.encode())
            f.write('\n'.encode())
            # print((tag).decode('cp437'))
            f.write(tag)
            f.write('\n'.encode())
            f.write(nonce)
            f.write('\n'.encode())
            f.write(e_message)

    @abstractmethod
    def _get_password(self):
        raise NotImplementedError


class PasswordGenerator(Writer):

    def __init__(self, domain, username, difficulty, length):
        super().__init__(domain, username)
        self.difficulty = difficulty
        self.length = length
        self.difficultyPool = {1: list(chain(self._range_between('a', 'z'), self._range_between('A', 'Z')))}
        self.difficultyPool[2] = list(chain(self.difficultyPool[1], self._range_between('0', '9')))
        self.difficultyPool[3] = list(chain(self.difficultyPool[2], self._range_between('!', '/')))

    @staticmethod
    def _range_between(first, last):
        return range(ord(first), ord(last) + 1)

    def _get_password(self):
        password = ''
        for i in range(0, self.length):
            password += chr(choice(self.difficultyPool[self.difficulty]))
        return password


class PasswordWriter(Writer):
    def __init__(self, domain, username):
        super().__init__(domain, username)

    def _get_password(self):
        return getpass('Password: ')


def clear():
    rmtree('passwords')
    os.mkdir('passwords')


class PasswordDeleter(AccountHandler):
    def delete(self):
        try:
            os.remove('passwords/' + self.file)
        except FileNotFoundError:
            print('Delete failed. Domain, username pair not found.')
