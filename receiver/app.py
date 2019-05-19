from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto import Cipher
from Crypto.Cipher import PKCS1_OAEP
import hashlib, binascii
import base64
from argparse import ArgumentParser
import os
import uuid 

base_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)),"keytemp")

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

@app.route('/pk',methods=["get"])
def get_pk():
    ey = RSA.generate(2048)
    hpwd = app.config.get("hpwd")
    key = RSA.generate(2048)
    if hpwd:
        exported_pem_key = key.export_key("PEM", passphrase=hpwd, pkcs=8)
    elif pwd and not salt:
        raise Exception("If you include a password, you must include a salt.")
    elif salt and not pwd:
        raise Exception("If you include a salt, you must include a password")
    else:
        print("WARNING: THIS PRIVATE KEY IS NOT PASSWORD PROTECTED")
        exported_pem_key = key.export_key("PEM")

    uid = str(uuid.uuid4())

    with open(os.path.join(base_dir, "private_{}.pem".format(str(uid))),"wb") as f:
        f.write(exported_pem_key)

    pub_key = key.publickey()

    ktext = pub_key.export_key("PEM")
    b64ktext = base64.b64encode(ktext)

    return jsonify({
        "id":uid,
        "key":b64ktext,
    })

@app.route('/send',methods=["post"])
def dec_post():
    b64_req_data = request.json["data"]
    uid = request.json["id"]
    req_data = base64.b64decode(b64_req_data)
    key_file = os.path.join(base_dir, "private_{}.pem".format(str(uid)))
    with open(key_file,"rb") as f:
        if app.config["hpwd"]:
            import_pass_key = RSA.import_key(f.read(), passphrase=app.config["hpwd"])
        else:
            print("WARNING: THIS PRIVATE KEY IS NOT PASSWORD PROTECTED")
            import_pass_key = RSA.import_key(f.read())
    os.remove(key_file)
    key_cipher = PKCS1_OAEP.new(import_pass_key)
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
    # clear text data contains the decrypted data posted  # 
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
    clear_text_data = key_cipher.decrypt(req_data)

    return jsonify({'status':'done'})


app.run()