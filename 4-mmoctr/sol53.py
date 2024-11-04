from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

H0 = b'0123456789abcdef'

def mmoctr(data):
    data = pad(data, AES.block_size)
    k = len(data)//AES.block_size
    Hi = H0
    for i in range(k):
        x = data[i*16:(i+1)*16]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    return Hi

def create_second_preimage(original_data):
    padded_data = pad(original_data, AES.block_size)
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    
    # Get the encryption of first block with H0
    cipher = AES.new(H0, AES.MODE_ECB)
    E_H0_x1 = cipher.encrypt(blocks[0])
    
    # Get H1 (before counter XOR)
    H1_no_counter = E_H0_x1
    
    # Create a new first block that will encrypt to H1_no_counter
    cipher_dec = AES.new(H0, AES.MODE_ECB)
    new_first_block = H1_no_counter  # Use the encrypted value directly as our new block
    
    # Build new file
    new_data = new_first_block + padded_data[16:]
    
    return new_data

def verify_collision(data1, data2):
    hash1 = mmoctr(data1)
    hash2 = mmoctr(data2)
    print(f"Hash 1: {hash1.hex()}")
    print(f"Hash 2: {hash2.hex()}")
    return hash1 == hash2

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Verify the collision works
    verify_collision(original_data, new_data)
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("Second preimage has been written to snd.bin")

if __name__ == "__main__":
    main()