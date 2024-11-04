#!/usr/bin/env python3

# A flawed variant of Matyas-Meyer-Oseas (MMO) hash function based on AES. 
# (c) Alwen Tiu, 2022

from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import *
import argparse 

H0=b'0123456789abcdef'


def mmoctr(data):
    data=pad(data, AES.block_size)

    k = len(data)//AES.block_size 

    Hi = H0 
    for i in range(0,k): 
        x = data[i*16:(i+1)*16]
        cipher=AES.new(Hi, AES.MODE_ECB)
        # H_{i} = enc(x, H_{i-1}) XOR i  
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))

    return Hi.hex()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help='file to compute the hash for')
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        data=f.read()
    digest = mmoctr(data)
    print("Hash: " + digest)

if __name__ == "__main__":
    main()
   