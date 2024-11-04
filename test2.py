#!/usr/bin/env python3 
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Util.strxor import *
from Crypto.Util.number import *
from Crypto.Util.Padding import * 

# default IV
IV=bytearray(b'fedcba9876543210')

def encrypt(data, key, IV):
    print("DEBUG: Data length before padding:", len(data))
    print("DEBUG: Data before padding (hex):", data.hex())
    
    cipher=AES.new(key, AES.MODE_CBC, IV)
    # apply PKCS7 padding prior to encryption
    padded_data = pad(data, AES.block_size)
    print("DEBUG: Data length after padding:", len(padded_data))
    print("DEBUG: Padded data (hex):", padded_data.hex())
    
    ct = cipher.encrypt(padded_data)
    print("DEBUG: Ciphertext length:", len(ct))
    print("DEBUG: Ciphertext (hex):", ct.hex())
    return ct

# generate a mac for a byte string directly
def gen_mac(data,key):
    ct = encrypt(data,key,bytes(IV))
    # use the last block of the ciphertext as the MAC
    mac = ct[-AES.block_size:]
    print("DEBUG: Final MAC:", mac.hex())
    return mac.hex()

def verify_mac(data,key,mac):
    m=gen_mac(data,key)
    return (m == mac)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('key', type=str, help='a 16-byte MAC key')
    parser.add_argument('file', type=str, help='input file to compute/verify MAC' )
    parser.add_argument('--iv', dest='iv', default='', help='a 16-byte IV value')
    parser.add_argument('--verify', dest='digest', default='', 
                      help='MAC value (in HEX)')
    args = parser.parse_args()

    if len(args.key) != 16:
        print("The MAC key must be 16 byte long")
        exit(1)

    key = (args.key).encode('utf-8')

    if len(args.iv) == 16:
        IV[0:16] = (args.iv).encode('utf-8')       
    elif args.iv != '':
        print("IV must be 16-byte long")
        exit(1)

    with open(args.file,'rb') as f:
        data = f.read()
        
    print("DEBUG: Input file size:", len(data))
    
    mac = gen_mac(data, key)
    
    if args.digest == '': 
        print('MAC: ' + mac)
    else:
        if (mac == args.digest):
            print('MAC verification succeeded')
        else:
            print('MAC verification failed')
            print('- Computed MAC: ' + mac)
            print('- Provided MAC: ' + args.digest)

if __name__ == "__main__":
    main()