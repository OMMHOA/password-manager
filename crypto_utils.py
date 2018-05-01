import binascii

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from getpass import getpass
from abc import ABC, abstractmethod


def _generate_key(password, salt, iter):
    key2 = binascii.hexlify(PBKDF2(password, salt))
    return key2


class AccountHandler:
    domain: str
    username: str
    file: str

    def __init__(self, domain, username):
        self.domain = domain
        self.username = username
        self.file = domain + '_' + username

    def write_db(self):
        with open('passwords/db', 'ab') as f:
            f.write(self.file.encode())


class DataWriter(ABC, AccountHandler):

    def __init__(self, domain, username):
        super().__init__(domain, username)

    def write_pass(self, m_pass):
        salt = 'randomsalt'
        iter = 1000
        key = _generate_key(m_pass, salt, iter)

        password = self._get_password()
        tag, nonce, e_pass = self.__encrypt(key, password.encode())
        self.__write_file(self.file, salt, tag, nonce, e_pass)

        print('Password Saved!')

    @staticmethod
    def __encrypt(key, password):
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(password)

        return tag, nonce, ciphertext

    @staticmethod
    def __write_file(file, salt, tag, nonce, e_pass):
        # print('Write\nsalt: '+salt+'\ntag: '+str(tag)+'\nnon: '+str(nonce)+'\nepass: '+str(e_pass))
        with open('passwords/' + file, 'wb') as f:
            f.write(salt.encode())
            f.write('\n'.encode())
            # print((tag).decode('cp437'))
            f.write(tag)
            f.write('\n'.encode())
            f.write(nonce)
            f.write('\n'.encode())
            f.write(e_pass)

        return e_pass, salt

    @abstractmethod
    def _get_password(self):
        raise NotImplementedError


class PasswordGenerator(DataWriter):
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


class PasswordWriter(DataWriter):
    def __init__(self, domain, username):
        super().__init__(domain, username)

    def _get_password(self):
        return getpass('Password: ')


class PasswordReader(AccountHandler):
    def read_pass(self, m_pass):
        e_pass, salt, tag, nonce = self.__read_file(self.file)
        key = _generate_key(m_pass, salt, tag)

        password = self.__decrypt(key, e_pass, nonce, tag)

        print(password)

    @staticmethod
    def __read_file(file):
        with open('passwords/' + file, 'rb') as f:
            salt = f.readline().rstrip()
            tag = f.readline().rstrip()
            nonce = f.readline().rstrip()
            e_pass = f.readline()
        # print('Read\nsalt: ' + salt + '\ntag: ' + str(tag) + '\nnon: ' + str(nonce) + '\nepass: ' + str(e_pass))
        return e_pass, salt, tag, nonce

    @staticmethod
    def __decrypt(k, ciphertext, nonce, tag):
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
