from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

H0 = b'0123456789abcdef'

def print_bytes_hex(data):
    """Print bytes in hex format"""
    print("Length:", len(data))
    print("Hex:", ' '.join(f'{b:02x}' for b in data))

def mmoctr(data):
    data = pad(data, AES.block_size)
    k = len(data)//AES.block_size
    Hi = H0
    
    print("\nHash calculation steps:")
    for i in range(k):
        x = data[i*16:(i+1)*16]
        print(f"\nBlock {i+1}:")
        print_bytes_hex(x)
        
        cipher = AES.new(Hi, AES.MODE_ECB)
        encrypted = cipher.encrypt(x)
        print(f"Encrypted with H{i}:")
        print_bytes_hex(encrypted)
        
        Hi = strxor(encrypted, long_to_bytes(i+1, AES.block_size))
        print(f"After XOR with {i+1}:")
        print_bytes_hex(Hi)
    
    return Hi

def create_second_preimage(original_data):
    print("\nOriginal data:")
    print_bytes_hex(original_data)
    
    padded_data = pad(original_data, AES.block_size)
    print("\nPadded data:")
    print_bytes_hex(padded_data)
    
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    print("\nBlocks:")
    for i, block in enumerate(blocks):
        print(f"\nBlock {i+1}:")
        print_bytes_hex(block)
    
    # Get the encryption of first block with H0
    cipher = AES.new(H0, AES.MODE_ECB)
    E_H0_x1 = cipher.encrypt(blocks[0])
    
    print("\nFirst block encryption with H0:")
    print_bytes_hex(E_H0_x1)
    
    # Get H1 (before counter XOR)
    H1_no_counter = E_H0_x1
    
    # Create a new first block that will encrypt to H1_no_counter
    cipher_dec = AES.new(H0, AES.MODE_ECB)
    new_first_block = cipher_dec.decrypt(H1_no_counter)
    
    print("\nNew first block:")
    print_bytes_hex(new_first_block)
    
    # Build new file
    new_data = new_first_block + padded_data[16:]
    
    print("\nNew complete data:")
    print_bytes_hex(new_data)
    
    return new_data

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    print("\n=== Original File Content ===")
    print_bytes_hex(original_data)
    
    new_data = create_second_preimage(original_data)
    
    # Calculate and print both hashes
    print("\n=== Hash Verification ===")
    print("Original hash:", mmoctr(original_data).hex())
    print("New hash:", mmoctr(new_data).hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("\nSecond preimage has been written to snd.bin")

if __name__ == "__main__":
    main()