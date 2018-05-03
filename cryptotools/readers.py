from abc import ABC, abstractmethod

from Crypto.Cipher import AES

from cryptotools.common import AccountHandler, generate_key


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


class DbReader(Reader):
    def read(self, m_pass):
        print('Domain: username')
        with open('passwords/db', 'rb') as f:
            lines = [line.rstrip() for line in f.readlines()]
            self.print_db_info(lines, m_pass)

    def print_db_info(self, lines, m_pass):
        i = 0
        while i < len(lines):
            salt = lines[i]
            tag = lines[i + 1]
            nonce = lines[i + 2]
            e_file = lines[i + 3]
            key = generate_key(m_pass, salt, tag)
            file = self._decrypt(key, e_file, nonce, tag)

            if file is None:
                print('File value is none. Something is wrong')
                return

            [domain, username] = str(file).split('__', 1)
            print(domain + ": " + username)
            i += 4
