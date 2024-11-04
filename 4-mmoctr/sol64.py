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
    # Step 1: Create first block of zeros
    block1 = bytes([0] * 16)
    
    # Step 2: Get H1 from encrypting zeros with H0
    cipher = AES.new(H0, AES.MODE_ECB)
    H1 = strxor(cipher.encrypt(block1), long_to_bytes(1, AES.block_size))
    print(f"H1 from zeros: {H1.hex()}")
    
    # Step 3: Get original H2 from fst.bin
    original_blocks = [original_data[i:i+16] for i in range(0, len(original_data), 16)]
    Hi = H0
    for i in range(2):  # Process first two blocks
        x = original_blocks[i]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    H2_original = Hi
    print(f"Original H2: {H2_original.hex()}")
    
    # Step 4: Subtract 2 from H2_original
    H2_minus_2 = strxor(H2_original, long_to_bytes(2, AES.block_size))
    print(f"H2 minus 2: {H2_minus_2.hex()}")
    
    # Step 5: Create second block by decrypting H2_minus_2 with H1
    cipher = AES.new(H1, AES.MODE_ECB)
    block2 = bytes([0] * 16)  # Second block of zeros
    print(f"Block 2: {block2.hex()}")
    
    # Step 6: Take third block from original data
    block3 = original_data[32:48]
    print(f"Block 3: {block3.hex()}")
    
    # Combine blocks to create second preimage
    new_data = block1 + block2 + block3
    
    return new_data

def verify_hashes(original_data, new_data):
    print("\nVerifying hashes step by step:")
    
    def print_hash_chain(data, label):
        print(f"\n{label}:")
        Hi = H0
        padded = pad(data, AES.block_size)
        for i in range(len(padded)//16):
            block = padded[i*16:(i+1)*16]
            cipher = AES.new(Hi, AES.MODE_ECB)
            encrypted = cipher.encrypt(block)
            Hi = strxor(encrypted, long_to_bytes(i+1, AES.block_size))
            print(f"Block {i+1}: {block.hex()}")
            print(f"H{i+1}: {Hi.hex()}")
    
    print_hash_chain(original_data, "Original")
    print_hash_chain(new_data, "Modified")

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Verify both produce same hash
    orig_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    print("\nResults:")
    print(f"Original data: {original_data.hex()}")
    print(f"New data:      {new_data.hex()}")
    print(f"Original hash: {orig_hash.hex()}")
    print(f"New hash:      {new_hash.hex()}")
    print(f"Target hash:   e758f7ce30186a937f073fd4ddab8393")
    
    if orig_hash == new_hash and original_data != new_data:
        print("\nFound valid second preimage!")
        with open('snd.bin', 'wb') as f:
            f.write(new_data)
    else:
        print("\nNo valid collision found")

if __name__ == "__main__":
    main()