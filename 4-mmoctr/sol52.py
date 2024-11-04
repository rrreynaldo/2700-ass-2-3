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

def find_collision(original_block):
    # Try to find a different block that gives the same hash value
    cipher = AES.new(H0, AES.MODE_ECB)
    original_encrypted = cipher.encrypt(original_block)
    
    # Get what the first block produces before the counter XOR
    H1_before_counter = strxor(original_encrypted, long_to_bytes(1, AES.block_size))
    
    # Try to find a different block that encrypts to give us H1_before_counter
    # We'll do this by decrypting H1_before_counter with a different key
    new_key = H1_before_counter  # Use the intermediate value as a new key
    cipher2 = AES.new(new_key, AES.MODE_ECB)
    new_block = cipher2.encrypt(original_block)  # Encrypt original block with new key
    
    return new_block

def create_second_preimage(original_data):
    padded_data = pad(original_data, AES.block_size)
    first_block = padded_data[:16]
    
    # Find a collision for the first block
    new_first_block = find_collision(first_block)
    
    # Create new data with the colliding first block
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