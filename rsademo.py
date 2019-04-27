#!/usr/bin/env python3
import rsa,base64,requests
from xml.dom import minidom
from Crypto.Cipher import AES
import xmltodict

PRIVATE_KEY_FILE = 'private.pem'
PUBLIC_KEY_FILE = 'public.pem'
SERVER_PUBLIC_KEY_FILE = 'server_pub.pem'
AES_KEY = b'00112233445566778899aabbccddeeff'
AES_IV  = b'0000000000000000'

HOST = '127.0.0.1'
PORT = 9999
#PORT = 9987
WS = 'request'

REQTEMPLATE = '''<request><enckey>%s</enckey><message>%s</message><signature>%s</signature></request>'''

def status(msg):
    print("[*] %s"%msg)

def initialiseRsa():
    status('Initialising RSA...')
    with open(PRIVATE_KEY_FILE, mode='rb') as privatefile:
       keydata = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata,format="PEM")

    with open(PUBLIC_KEY_FILE, mode='rb') as publicfile:
       keydata = publicfile.read()
    pubkey = rsa.PublicKey.load_pkcs1(keydata,format="PEM")
    
    with open(SERVER_PUBLIC_KEY_FILE, mode='rb') as publicfile:
       keydata = publicfile.read()
    serverpubkey = rsa.PublicKey.load_pkcs1(keydata,format="PEM")

    return (serverpubkey,privkey,pubkey)

def signMessage(msg,pubkey):
    status('Signing message...')
    return rsa.sign(msg,pubkey,'SHA-1')

def encryptRSA(msg,pubkey):
    status('RSA encrypting message...')
    return rsa.encrypt(msg,pubkey)

def encryptAES(msg):
    status('AES Encrypting message...')
    aes = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    ciphertext = aes.encrypt(msg)
    return ciphertext

def decryptAES(msg,key,iv):
    status('AES decrypting message...')
    #status(iv)
    #status(key)
    aes = AES.new(key, AES.MODE_CBC, iv)
    cleartext = aes.decrypt(msg)
    return cleartext 

(serverpubkey,privkey,pubkey) = initialiseRsa()

message = b'The answer is no' 
encmessage = encryptAES(message)
enckey = encryptRSA(b'%s|%s'%(AES_KEY,AES_IV),serverpubkey)
signature = signMessage(encmessage,privkey)

xmltext = REQTEMPLATE%(base64.b64encode(enckey).decode('ascii'),base64.b64encode(encmessage).decode('ascii'), base64.b64encode(signature).decode('ascii'))
xmldoc = minidom.parseString(xmltext)
print(xmldoc.toprettyxml())

status('Sending message to http://%s:%s/%s...'%(HOST,PORT,WS))
backmsg = requests.post("http://%s:%s/%s"%(HOST,PORT,WS), data=xmltext).text
back = xmltodict.parse(backmsg)['response']
backplain = decryptAES(base64.b64decode(back),AES_KEY,AES_IV)
status ('Returned message is: %s'%backplain.decode('ascii'))


