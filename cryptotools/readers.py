from abc import ABC, abstractmethod

from Crypto.Cipher import AES

from cryptotools.common import AccountHandler, generate_key
from os import listdir


class Reader(ABC):
    @abstractmethod
    def read(self, m_pass):
        raise NotImplementedError

    @staticmethod
    def _decrypt(k, ciphertext, nonce, tag):
        cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return plaintext
        except ValueError:
            print("Key incorrect or message corrupted")


class PasswordReader(AccountHandler, Reader):
    def read(self, m_pass):
        salt, tag, nonce, e_pass = self._read_file()
        key = generate_key(m_pass, salt, tag)

        message = self._decrypt(key, e_pass, nonce, tag)

        print(message)

    def _read_file(self):
        with open('passwords/' + self.file, 'rb') as f:
            lines = [line.rstrip() for line in f.readlines()]
            return tuple(lines)


class List(Reader):
    def read(self, m_pass):
        print('domain: username')
        for f in listdir('passwords'):
            [domain, username] = f.split('__', 1)
            print('%s: %s' % (domain, username))
