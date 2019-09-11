#!/usr/bin/env python3
import rsa,base64,requests
from xml.dom import minidom
from Crypto.Cipher import AES
import xmltodict

PRIVATE_KEY_FILE = 'private.pem'
PUBLIC_KEY_FILE = 'public.pem'
SERVER_PUBLIC_KEY_FILE = 'server_pub.pem'
AES_KEY = b'00112233445566778899aabbccddeeff'
AES_IV  = b'1111111111111111'

#HOST = 'https://singleframesecurity.net'
HOST = 'http://127.0.0.1'
PORT = 9999
#PORT = 9987
WS = 'request'

REQTEMPLATE = '''<request><enckey>%s</enckey><message>%s</message><signature>%s</signature></request>'''

def status(msg):
    print("[*] %s"%msg)

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

def signMessage(msg,key):
    status('Signing message...')
    return rsa.sign(msg,key,'SHA-1')

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

#message = b'The answer is noThe answer is no'
message = b'0123456789ab'
message = pad_pkcs7(message) 
encmessage = encryptAES(message)
enckey = encryptRSA(b'%s|%s'%(AES_KEY,AES_IV),serverpubkey)
signature = signMessage(encmessage,privkey)

xmltext = REQTEMPLATE%(base64.b64encode(enckey).decode('ascii'),base64.b64encode(encmessage).decode('ascii'), base64.b64encode(signature).decode('ascii'))
xmldoc = minidom.parseString(xmltext)
print(xmldoc.toprettyxml())

status('Sending message to %s:%s/%s...'%(HOST,PORT,WS))
backmsg = requests.post("%s:%s/%s"%(HOST,PORT,WS), data=xmltext).text
back = xmltodict.parse(backmsg)['response']
backplain = decryptAES(base64.b64decode(back),AES_KEY,AES_IV)
status ('Returned message is: %s'%backplain.decode('ascii'))


