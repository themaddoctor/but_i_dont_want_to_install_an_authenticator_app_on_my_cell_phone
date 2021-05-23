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

from sys import argv
from time import time
from os import path
#from PIL import ImageGrab as screenshot # only on Mac and Windows
from pyscreenshot import grab as screenshot # also requires easyprocess
from pyzbar.pyzbar import decode as qrdecode
import re

from hashlib import sha1, sha256, sha512
from base64 import b32decode
from hmac import HMAC

storage = ".authentications"

def bytes_to_int(x:bytes):
    return int.from_bytes(x,"big")

def int_to_bytes(n:int,length=False):
    if not length:
        length = ceiling(bitlength(n),8)
    return n.to_bytes(length,"big")

def urldecode(encoded):
    result = b""
    i = 0
    while i < len(encoded):
        if encoded[i] == "%":
            result += bytes.fromhex(encoded[i+1:i+3])
            i += 3
        else:
            result += encoded[i].decode()
            i += 1
    return result

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
    service = urldecode(service).decode("utf-8")
    pairs = remainder.split("&")
    issuer = ""
    digits = 6
    period = 30
    algorithm = "sha1"
    for pair in pairs:
        key,value = pair.split("=")
        if key == "issuer":
            issuer = urldecode(value).decode("utf-8")
        elif key == "secret":
            secret = value.upper()
        elif key == "algorithm":
            algorithm = value.lower()
        elif key == "digits":
            digits = int(value)
        elif key == "period":
            period = int(value)
    return service,issuer,secret,digits,period,algorithm

def read_storage(storage:str,which:str):
    results = []
    with open(storage,"r") as infile:
        for line in infile:
            matches = re.findall(which.lower(),(line.split("|")[0]+line.split("|")[1]).lower())
            if matches:
                service,issuer,secret,digits,period,algorithm = line.replace("\n","").split("|")
                digits = int(digits)
                period = int(period)
                results.append((service,issuer,secret,digits,period,algorithm))
    return results

def add_to_storage(storage:str,service:str,issuer:str,secret:str,digits:int,period:int,algorithm:str):
    matches = read_storage(storage,service+issuer)
    if len(matches) > 0:
        print("that service is already stored")
    else:
        outfile = open(path.expanduser('~')+"/"+storage,"a")
        outfile.write(service + "|" + issuer + "|" + secret + "|" + str(digits) + "|" + str(period) + "|" + str(algorithm) + "\n")
        outfile.close()

def scan():
    image = screenshot()
    uris = qrdecode(image)
    if len(uris) == 0:
        return False
    uri = uris[0].data.decode("utf-8")
    return uri

if len(argv) == 1: # scan desktop
    uri = scan()
    if uri:
        service,issuer,secret,digits,period,algorithm = parse_URI(uri)
        print("adding service \"" + service + "\" from",issuer)
        add_to_storage(storage,service,issuer,secret,digits,period,algorithm)
        print(generate_OTP(secret,digits,period,algorithm))
    else:
        print("QR code not seen")
elif argv[1][:15] == "otpauth://totp/":
    uri = argv[1][:]
    service,issuer,secret,digits,period,algorithm = parse_URI(uri)
    print("adding service \"" + service + "\" from",issuer)
    add_to_storage(storage,service,issuer,secret,digits,period,algorithm)
    print(generate_OTP(secret,digits,period,algorithm))
else: # use command-line argument to select service
    matches = read_storage(storage,argv[1])
    if len(matches) == 0:
        print("not found")
    else:
        for match in matches:
            service,issuer,secret,digits,period,algorithm = match
            print(issuer,":",service,":",generate_OTP(secret,digits,period,algorithm))
