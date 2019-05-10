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
        print("msg: %s"%msg)
        print("signature: %s"%signature)
        print("pubkey: %s"%pubkey)
        rsa.verify(msg,signature,pubkey)
        status('Verified.')
        return True
    except:
        status('! Verification error')
        return False

def unpad_pkcs7(b):
    """Strips PKCS#7 padding from the end of the given byte array and returns
    the stripped byte array.

    Parameters:
        b (bytes): the input array

    Returns:
        bytes: the input array without the trailing PKCS#7 padding
    """
    status('pkcs7 unpad %s'%b)
    back = b[:-b[len(b)-1]]
    status('unpadded %s'%back)
    return back

def pad_pkcs7(b, block_size=16):
    """Applies PKCS#7 padding to the end of the given byte array such that its
    length becomes divisible with the given block size, in bytes.
    Parameters:
        b (bytes): the input array
        block_size (int): the block size to pad to
    """
    extra = block_size - (len(b) % block_size)
    padding = bytes([extra]) * extra
    return b + padding

def encryptAES(msg,key,iv):
    status('AES Encrypting message...')
    aes = AES.new(key, AES.MODE_CBC, iv)
    msg = pad_pkcs7(msg)
    ciphertext = aes.encrypt(msg)
    return ciphertext

def decryptAES(msg,key,iv):
    status('AES decrypting message...')
    status('MSG:%s\nKEY:%s\nIV:%s\n'%(msg,key,iv))
    #status(iv)
    #status(key)
    aes = AES.new(key, AES.MODE_CBC, iv)
    cleartext = aes.decrypt(msg)
    return cleartext

@app.route("/request",methods=["POST","GET"])
def processRequest():
    back = ""
    if (request.method == 'POST'):
        print(request.data)
        status("Message received.")
        try:
            payloadxml = xmltodict.parse(request.data)
            if(payloadxml['request']['signature']==None):
                signature = ''
            else:
                signature = base64.b64decode(payloadxml['request']['signature'])
            enckey = base64.b64decode(payloadxml['request']['enckey'].replace('\n',''))
            message = base64.b64decode(payloadxml['request']['message'].replace('\n',''))
        except Exception as e:
            status('Exception at xml parsing')
            raise e

        aesKeyData = decryptRSA(enckey)
        status(aesKeyData)
        AES_KEY = aesKeyData[0:32]
        AES_IV = aesKeyData[33:]
        plainmsg = unpad_pkcs7(decryptAES(message,AES_KEY,AES_IV))
        status('Message decrypted, text: %s'%plainmsg)
        if (verifySig(message,signature,clientpubkey)):
            msg = b'Simon says %s'%plainmsg
            #msg = plainmsg
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
app.run(host='0.0.0.0', port=PORT_NUMBER, debug=True,ssl_context=('ssl/fullchain3.pem','ssl/privkey3.pem'))
