import binascii

from Crypto.Protocol.KDF import PBKDF2


def generate_key(password, salt, iter):
    key2 = binascii.hexlify(PBKDF2(password, salt))
    return key2


class AccountHandler:

    def __init__(self, domain, username):
        self.domain = domain
        self.username = username
        self.file = domain + '__' + username
