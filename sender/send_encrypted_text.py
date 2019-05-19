import requests
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from argparse import ArgumentParser

def encrypt_and_post(clear_text):

    j = requests.get("http://localhost:5000/pk", verify=False).json()

    i = j["id"]
    pkey = base64.b64decode(j["key"])
    loaded_key = RSA.import_key(pkey)
    pub_cipher = PKCS1_OAEP.new(loaded_key)
    assert pub_cipher.can_encrypt()
    enc = pub_cipher.encrypt(clear_text)
    encb64data = base64.b64encode(enc)

    r = requests.post("http://localhost:5000/send", json={"id":i,"data":encb64data}, verify=False)


if __name__=="__main__":
    parser = ArgumentParser()
    parser.add_argument('-t')
    args = parser.parse_args()
    clear_text = args.t
    encrypt_and_post(clear_text)