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
    # Pad original data
    padded_data = pad(original_data, AES.block_size)
    
    # Get first block and its hash
    first_block = padded_data[:16]
    cipher = AES.new(H0, AES.MODE_ECB)
    encrypted_first = cipher.encrypt(first_block)
    H1 = strxor(encrypted_first, long_to_bytes(1, AES.block_size))
    
    # To create a collision, we need:
    # encrypt(new_block, H0) XOR 1 = H1
    # Therefore: encrypt(new_block, H0) = H1 XOR 1
    target_encryption = strxor(H1, long_to_bytes(1, AES.block_size))
    
    # Create a new first block that encrypts to target_encryption
    # In ECB mode with the same key, we can decrypt target_encryption
    # to get our new first block
    cipher = AES.new(H0, AES.MODE_ECB)
    new_first_block = cipher.decrypt(target_encryption)
    
    # Combine new first block with remaining blocks
    new_data = new_first_block + padded_data[16:]
    
    return new_data

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Verify both produce same hash
    print(f"Original hash: {mmoctr(original_data).hex()}")
    print(f"New hash: {mmoctr(new_data).hex()}")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("Second preimage has been written to snd.bin")

if __name__ == "__main__":
    main()