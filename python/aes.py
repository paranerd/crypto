# sudo apt install python3-pip
# pip3 install pycrypto

import base64
import hashlib
import string
import random
import getpass
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Hash import SHA, SHA256, HMAC

class My_AES():
    def __init__(self):
        self.blockSize = 16
        self.keySize = 32 # 32 bytes for aes 256 bit

    def generate_key(self, secret, salt):
        return KDF.PBKDF2(secret, salt, self.keySize, 2048)

    def random_string(self, length):
        return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))

    def encrypt(self, plaintext="", secret="", sign=False, is_file=False):
        # Check if plaintext was passed
        if not plaintext:
            if not is_file:
                plaintext = input('Enter text to encrypt: ')

        # Check if secret was passed
        if not secret:
            secret = getpass.getpass('Enter secret: ')

        # Generate IV
        iv = Random.new().read(self.blockSize)

        # Generate salt
        salt = Random.new().read(self.blockSize)

        # Generate key
        key = self.generate_key(secret, salt)

        # Encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(self.pkcs5_pad(plaintext))

        # Encode
        enc64 = self.base64_url_encode(iv + salt + enc)

        # Sign
        if (sign):
            enc64 = enc64 + ":" + self.sign(enc64, key)

        return enc64

    def decrypt(self, encrypted64="", secret="", is_file=False):
        if not encrypted64:
            if is_file:
                print("No data to decrypt")
                return ""
            else:
                encrypted64 = input("Enter encrypted data: ")

        # Check if secret was passed
        if not secret:
            secret = getpass.getpass('Enter secret: ')

        # Separate payload from potential hmac
        separated = encrypted64.strip().split(":")

        # Extract HMAC if signed
        hmac = separated[1] if len(separated) > 1 else ""

        # Decode
        enc = self.base64_url_decode(separated[0])

        # Extract IV
        iv = enc[0:self.blockSize]

        # Extract salt
        salt = enc[self.blockSize:self.blockSize + self.blockSize]

        # Extract ciphertext
        ciphertext = enc[self.blockSize + self.blockSize:]

        # Generate key
        key = self.generate_key(secret, salt)

        if (hmac and not (self.sign(separated[0], key) == hmac)):
            return None

        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # Unpad and format
        return self.pkcs5_unpad(decrypted.decode('utf-8'))

    def encrypt_file(self, path="", secret=""):
        if not path:
            path = input("Enter path: ")

        if not secret:
            secret = getpass.getpass('Enter secret: ')

        with open(path, 'rb') as fo:
            plaintext = fo.read()
            enc = self.encrypt(plaintext, secret)

        with open(path + ".enc", 'wb') as fo:
            fo.write(enc)

        return path + ".enc"

    def decrypt_file(self, path="", secret=""):
        if not path:
            path = input("Enter path: ")

        if not secret:
            secret = getpass.getpass('Enter secret: ')

        # Read file
        with open(path, 'rb') as fo:
            ciphertext = fo.read()

        # Decrypt
        plaintext = self.decrypt(ciphertext, secret, True)

        # Build destination path
        destPath = path.rsplit('.enc', 1)[0]

        # Write file
        with open(destPath, 'wb') as fo:
            fo.write(plaintext)

        return destPath

    def pkcs5_pad(self, s):
        return s + (self.blockSize - len(s) % self.blockSize) * chr(self.blockSize - len(s) % self.blockSize)

    def pkcs5_unpad(self, s):
        return s[0:-ord(s[-1])]

    def base64_url_encode(self, s):
        return base64.b64encode(s, altchars=b'-_').decode('utf-8')

    def base64_url_decode(self, s):
        return base64.b64decode(s.encode(), altchars=b'-_')

    def sign(self, str, key):
        myhash = HMAC.new(key, digestmod=SHA256)
        myhash.update(str)
        return myhash.hexdigest()

class Main():
    @staticmethod
    def menu():
        crypt = My_AES()
        print("--- Main Menu ---")
        print("[1] Encrypt Text")
        print("[2] Decrypt Text")
        print("[3] Encrypt File")
        print("[4] Decrypt File")
        print("[5] Exit")

        selection = input("Select: ")
        print

        if selection == '1':
            print("\nResult: " + crypt.encrypt())
        elif selection == '2':
            print("\nResult: " + crypt.decrypt())
        elif selection == '3':
            print("\nResult: " + crypt.encrypt_file())
        elif selection == '4':
            print("\nResult: " + crypt.decrypt_file())
        elif selection == '5':
            return
        else:
            print("Illegal selection")

        print

        return Main().menu()

Main().menu()
