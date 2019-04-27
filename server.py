#!/usr/bin/env python3
from flask import Flask
from flask import make_response, render_template, redirect
from flask import request
import rsa,base64,requests
from xml.dom import minidom
import xmltodict
from Crypto.Cipher import AES

'''
<?xml version="1.0" ?>
<request>
    <enckey>base64(RSAEncrypt(AES_KEY))</enckey>
    <message>base64(AES(msg,AES_KEY))</message>
    <signature>base64(RSASign(AES(msg,AES_KEY),'SHA-1'))</signature>
</request>

<response>
    base64(AES(back,AES_KEY))
</response>
'''
RESPTEMPLATE = '''<response>%s</response>'''
PRIVATE_KEY_FILE = 'server_priv.pem'
PUBLIC_KEY_FILE = 'server_pub.pem'
CLIENT_PUBLIC_KEY_FILE = 'public.pem'
PORT_NUMBER = 9999

app = Flask(__name__)

def status(msg):
    print("[*] %s"%msg)

@app.route("/")
def hello():
    return "Hello World!"

def decryptRSA(msg):
    status('RSA decrypting message...')
    return rsa.decrypt(msg,privkey)

def verifySig(msg,signature,pubkey):
    status('Verifying...')
    try:
        rsa.verify(msg,signature,pubkey)
        status('Verified.')
        return True
    except:
        status('! Verification error')
        return False

def encryptAES(msg,key,iv):
    status('AES Encrypting message...')
    aes = AES.new(key, AES.MODE_CBC, iv)
    extra = len(msg) % 16
    if extra > 0:
        msg = msg + (b' ' * (16 - extra))
    ciphertext = aes.encrypt(msg)
    return ciphertext

def decryptAES(msg,key,iv):
    status('AES decrypting message...')
    #status(iv)
    #status(key)
    aes = AES.new(key, AES.MODE_CBC, iv)
    cleartext = aes.decrypt(msg)
    return cleartext    

@app.route("/request",methods=["POST","GET"])
def processRequest():
    back = ""
    if (request.method == 'POST'):
        status("Message received. Parsing...")
        try:
            payloadxml = xmltodict.parse(request.data)
            enckey = base64.b64decode(payloadxml['request']['enckey'])
            message = base64.b64decode(payloadxml['request']['message'])
            signature = base64.b64decode(payloadxml['request']['signature'])
        except Exception as e:
            status('Exception at xml parsing')
            raise e

        aesKeyData = decryptRSA(enckey)
        status(aesKeyData)
        AES_KEY = aesKeyData[0:32]
        AES_IV = aesKeyData[33:]
        plainmsg = decryptAES(message,AES_KEY,AES_IV)
        status('Message decrypted, text: %s'%plainmsg)
        if (verifySig(message,signature,clientpubkey)):
            msg = b'Simon says %s'%plainmsg
            cipmsg = encryptAES(msg,AES_KEY,AES_IV)
            back += RESPTEMPLATE%base64.b64encode(cipmsg).decode('ascii')
        else:
            back+="Verification error"
    else:
        status("GET received, returning page")
        back+="<html>GET received</html>"
    return back

def initialiseRsa():
    status('Initialising RSA...')
    with open(PRIVATE_KEY_FILE, mode='rb') as privatefile:
       keydata = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata,format="PEM")

    with open(PUBLIC_KEY_FILE, mode='rb') as publicfile:
       keydata = publicfile.read()
    pubkey = rsa.PublicKey.load_pkcs1(keydata,format="PEM")
    
    with open(CLIENT_PUBLIC_KEY_FILE, mode='rb') as publicfile:
       keydata = publicfile.read()
    clientpubkey = rsa.PublicKey.load_pkcs1(keydata,format="PEM")

    return (clientpubkey,privkey,pubkey)

(clientpubkey,privkey,pubkey) = initialiseRsa()
app.run(host='0.0.0.0', port=PORT_NUMBER, debug=True)
