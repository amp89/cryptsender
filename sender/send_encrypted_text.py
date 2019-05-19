import requests
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

b64pkey = requests.get("http://localhost:5000/pk", verify=False).text
print(b64pkey)
pkey = base64.b64decode(b64pkey)


loaded_key = RSA.import_key(pkey)
pub_cipher = PKCS1_OAEP.new(loaded_key)

pub_cipher.can_encrypt()
enc = pub_cipher.encrypt("OH WOW IT WORKS")
encb64data = base64.b64encode(enc)

r = requests.post("http://localhost:5000/send", json={"data":encb64data}, verify=False)