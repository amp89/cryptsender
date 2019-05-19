from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto import Cipher
from Crypto.Cipher import PKCS1_OAEP
import hashlib, binascii
import base64
from argparse import ArgumentParser

def create_app(hpwd_hex):
    app = Flask(__name__)
    app.config['hpwd'] = hpwd_hex
    print('Passed item: ', app.config['hpwd'])
    return app

parser = ArgumentParser()
parser.add_argument('-p')
parser.add_argument('-s')
args = parser.parse_args()
pwd = args.p
salt = args.s
hpwd_hex = None
if pwd and salt:
    hpwd = hashlib.pbkdf2_hmac('sha256',pwd,salt,1000000)
    del pwd
    hpwd_hex = binascii.hexlify(hpwd)
elif pwd and not salt:
    raise Exception("If you include a password, you must include a salt.")
elif salt and not pwd:
    raise Exception("If you include a salt, you must include a password")
else:
    print("WARNING: THIS PRIVATE KEY IS NOT PASSWORD PROTECTED")

app = create_app(hpwd_hex)
# @app.route('/')
# def hello_world():
#     return 'Hello, World!'

@app.route('/pk',methods=["get"])
def get_pk():
    with open("public.pub","rb") as f:
        ktext = f.read()
    return base64.b64encode(ktext)

@app.route('/send',methods=["post"])
def dec_post():
    b64_req_data = request.json["data"]
    req_data = base64.b64decode(b64_req_data)
    with open("private.pem","rb") as f:
        if app.config["hpwd"]:
            import_pass_key = RSA.import_key(f.read(), passphrase=app.config["hpwd"])
        else:
            print("WARNING: THIS PRIVATE KEY IS NOT PASSWORD PROTECTED")
            import_pass_key = RSA.import_key(f.read())
    print dir(Cipher)
    key_cipher = PKCS1_OAEP.new(import_pass_key)
    dec_req_data = key_cipher.decrypt(req_data)
    print(dec_req_data)
    return 'Done'


app.run()