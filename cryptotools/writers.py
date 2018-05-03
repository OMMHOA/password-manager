from Crypto.Cipher import AES
from getpass import getpass
from abc import ABC, abstractmethod
from shutil import rmtree
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
        file_tag, file_nonce, e_file = self.__get_encrypted_message(self.file, m_pass)
        try:
            self.__write_file(self.file, tag, nonce, e_pass)
            self.__write_file('db', file_tag, file_nonce, e_file)
        except IOError:
            print('Failed to save password. Rolling back...')
            self.__rollback()
            print('Rollback done.')
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
        with open('passwords/' + file, 'ab') as f:
            f.write(self.salt.encode())
            f.write('\n'.encode())
            # print((tag).decode('cp437'))
            f.write(tag)
            f.write('\n'.encode())
            f.write(nonce)
            f.write('\n'.encode())
            f.write(e_message)
            f.write('\n'.encode())

    def __rollback(self):
        os.remove('passwords/' + self.file)
        self.__remove_from_db()

    def __remove_from_db(self):
        with open('passwords/db', 'rb+') as f:
            db = f.readlines()
            f.seek(0)
            self.__write_if_not_file(db, f)
            f.truncate()

    def __write_if_not_file(self, db, open_file):
        for i in db:
            if i != self.file.encode():
                open_file.write(i)

    @abstractmethod
    def _get_password(self):
        raise NotImplementedError


class PasswordGenerator(Writer):
    difficulty: int
    length: int

    def __init__(self, domain, username, difficulty, length):
        super().__init__(domain, username)
        self.difficulty = difficulty
        self.length = length

    def _get_password(self):
        # TODO generate password with int self.difficulty, int self.length
        # For help: ./password-manager.py generate --help
        return "password"


class PasswordWriter(Writer):
    def __init__(self, domain, username):
        super().__init__(domain, username)

    def _get_password(self):
        return getpass('Password: ')


def clear():
    rmtree('passwords')
    os.mkdir('passwords')
