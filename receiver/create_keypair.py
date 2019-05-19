from flask import Flask
from Crypto.PublicKey import RSA
from Crypto import Cipher
import hashlib, binascii
import base64
from argparse import ArgumentParser

def refresh_key(pwd=None, salt=None):
    
    key = RSA.generate(2048)
    if pwd and salt:
        hpwd = hashlib.pbkdf2_hmac('sha256',pwd,salt,1000000)
        del pwd
        hpwd_hex = binascii.hexlify(hpwd)
        exported_pem_key = key.export_key("PEM", passphrase=hpwd_hex, pkcs=8)
    elif pwd and not salt:
        raise Exception("If you include a password, you must include a salt.")
    elif salt and not pwd:
        raise Exception("If you include a salt, you must include a password")
    else:
        print("WARNING: THIS PRIVATE KEY IS NOT PASSWORD PROTECTED")
        exported_pem_key = key.export_key("PEM")



    with open("private.pem","wb") as f:
        f.write(exported_pem_key)

    pub_key = key.publickey()

    with open("public.pub","wb") as f:
        f.write(pub_key.export_key("PEM"))

if __name__=="__main__":
    parser = ArgumentParser()
    parser.add_argument('-p')
    parser.add_argument('-s')
    args = parser.parse_args()
    pwd = args.p
    salt = args.s
    refresh_key(pwd=pwd, salt=salt)