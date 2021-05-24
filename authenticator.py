#!/usr/bin/env python3

# authenticator.py

# see http://www.rfc-editor.org/rfc/rfc6238.txt
#     http://github.com/google/google-authenticator/wiki/Key-Uri-Format

# contents of URI:
#     otpauth://totp/ or hotp
#     service (in URL-safe string)
#     secret (base32)
#     issuer (in URL-safe string)
#     algorithm (sha1, sha256, sha512)
#     digits (6, 7, 8)
#     period or counter

from sys import argv, stdout
from time import time
from os import path
#from PIL import ImageGrab as screenshot # only on Mac and Windows
from pyscreenshot import grab as screenshot # also requires easyprocess
from pyzbar.pyzbar import decode as qrdecode
import re
from hashlib import sha1, sha256, sha512
from base64 import b32decode
from hmac import HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from getpass import getpass
from random import randrange

storage = ".authentications"

def bytes_to_int(x:bytes):
    return int.from_bytes(x,"big")

def int_to_bytes(n:int,length=False):
    if not length:
        length = ceiling(bitlength(n),8)
    return n.to_bytes(length,"big")

def urldecode(encoded):
    result = ""
    i = 0
    while i < len(encoded):
        if encoded[i] == "%":
            result += chr(int(encoded[i+1:i+3],16))
            i += 3
        else:
            result += encoded[i]
            i += 1
    return result

def xor(x,y):
    if len(x) != len(y):
        raise Exception("unequal lengths")
    result = b""
    for i in range(len(x)):
        result += (x[i]^y[i]).to_bytes(1,"big")
    return result

def pbkdf2(password:str,salt:bytes,iterations:int,keylength:int,hashalgo=sha1,prf=HMAC):
    hashlength = len(hashalgo(b"").digest())
    result = b""
    for i in range(keylength//hashlength + (keylength%hashlength != 0)):
        pseudorand = prf(password.encode("utf-8"),salt+(i+1).to_bytes(4,"big"),hashalgo).digest()
        F = pseudorand[:]
        for _ in range(iterations-1):
            pseudorand = prf(password.encode("utf-8"),pseudorand,hashalgo).digest()
            F = xor(F,pseudorand)
        result += F
    return result[:keylength]

def write_file(filename:str,key:bytes,salt:bytes,iv:bytes,data:str):
    encryptor = AES.new(key,AES.MODE_CBC,iv)
    encrypted = encryptor.encrypt(pad(data.encode("UTF-8"),16))
    outfile = open(filename,"wb")
    if not outfile:
        raise Exception("failed to create file")
    outfile.write(salt)
    outfile.write(iv)
    outfile.write(encrypted)
    outfile.close()
    return

def read_file(filename:str,password:str):
    try:
        infile = open(filename,"rb").read()
    except:
        raise Exception("failed to open file")
    salt = infile[0:16]
    iv = infile[16:32]
    encrypted = infile[32:]
    key = pbkdf2(password,salt,128,32)
    encryptor = AES.new(key,AES.MODE_CBC,iv)
    data = unpad(encryptor.decrypt(encrypted),16).decode("UTF-8")
    return key,salt,iv,data

def generate_OTP(secret:str,digits=6,period=30,hashalgo=sha1):
    if type(hashalgo) == str:
        hashalgo = eval(hashalgo)
    h = HMAC(b32decode(secret),int_to_bytes(int(time()/period),8),hashalgo).digest()
    offset = h[-1] & 0xf
    otp = bytes_to_int(h[offset:offset+4]) & 0x7fffffff
    otp = str(otp)
    while len(otp) < 8:
        otp = "0" + otp
    return otp[-digits:]

def parse_URI(uri:str):
    if uri[:15] != "otpauth://totp/":
        print("invalid or unsupported URI")
        return False
    remainder = uri[15:]
    service,remainder = remainder.split("?")
    service = urldecode(service)
    pairs = remainder.split("&")
    issuer = ""
    digits = 6
    period = 30
    algorithm = "sha1"
    for pair in pairs:
        key,value = pair.split("=")
        if key == "issuer":
            issuer = urldecode(value)
        elif key == "secret":
            secret = value.upper()
        elif key == "algorithm":
            algorithm = value.lower()
        elif key == "digits":
            digits = int(value)
        elif key == "period":
            period = int(value)
    return service,issuer,secret,digits,period,algorithm

def read_storage(data:str,which:str):
    results = []
    for line in data.split("\n")[:-1]:
        matches = re.findall(which.lower(),(line.split("|")[0]+line.split("|")[1]).lower())
        if matches:
            service,issuer,secret,digits,period,algorithm = line.split("|")
            digits = int(digits)
            period = int(period)
            results.append((service,issuer,secret,digits,period,algorithm))
    return results

def add_to_storage(data:str,service:str,issuer:str,secret:str,digits:int,period:int,algorithm:str):
    matches = read_storage(data,service+issuer)
    if len(matches) > 0:
        print("that service is already stored")
    else:
        newdata = service + "|" + issuer + "|" + secret + "|" + str(digits) + "|" + str(period) + "|" + str(algorithm) + "\n"
        data += newdata
    return data

def scan():
    image = screenshot()
    uris = qrdecode(image)
    if len(uris) == 0:
        return False
    uri = uris[0].data.decode("utf-8")
    return uri

password = getpass("password: ")
if not path.exists(storage):
    print("creating local storage")
    salt = b""
    for _ in range(16):
        salt += randrange(256).to_bytes(1,"big")
    iv = b""
    for _ in range(16):
        iv += randrange(256).to_bytes(1,"big")
    data = ""
    key = pbkdf2(password,salt,128,32)
else:
    key,salt,iv,data = read_file(storage,password)

if (len(argv) == 1) or (argv[1] == "--scan"): # scan desktop
    uri = scan()
    if uri:
        service,issuer,secret,digits,period,algorithm = parse_URI(uri)
        print("adding service \"" + service + "\" from \"" + issuer + "\"")
        data = add_to_storage(data,service,issuer,secret,digits,period,algorithm)
        print("code:",generate_OTP(secret,digits,period,algorithm))
        write_file(storage,key,salt,iv,data)
    else:
        print("QR code not seen")
elif argv[1] == "--dump":
    stdout.write(data)
elif argv[1][:15] == "otpauth://totp/":
    uri = argv[1][:]
    service,issuer,secret,digits,period,algorithm = parse_URI(uri)
    print("adding service \"" + service + "\" from \"" + issuer + "\"")
    data = add_to_storage(data,service,issuer,secret,digits,period,algorithm)
    print("code:",generate_OTP(secret,digits,period,algorithm))
    write_file(storage,key,salt,iv,data)
else: # use command-line argument to select service
    matches = read_storage(data,argv[1])
    if len(matches) == 0:
        print("not found")
    else:
        for match in matches:
            service,issuer,secret,digits,period,algorithm = match
            print(issuer,":",service,":",generate_OTP(secret,digits,period,algorithm))
