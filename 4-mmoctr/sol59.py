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

def find_collision_block():
    # Original first block
    original_block = bytes.fromhex('a4048d07f516b94a43aa3d8f4ddc341a')
    
    # Calculate H1 for original block
    cipher = AES.new(H0, AES.MODE_ECB)
    encrypted = cipher.encrypt(original_block)
    H1_target = strxor(encrypted, long_to_bytes(1, AES.block_size))
    
    # For H1 to be the same, we need:
    # E_{H0}(new_block) ⊕ 1 = H1_target
    # Therefore: E_{H0}(new_block) = H1_target ⊕ 1
    
    target_encryption = strxor(H1_target, long_to_bytes(1, AES.block_size))
    
    # To get a block that encrypts to target_encryption:
    cipher_dec = AES.new(H0, AES.MODE_ECB)
    new_block = cipher_dec.decrypt(target_encryption)
    
    # Verify it's different from original
    if new_block == original_block:
        print("Found same block, trying alternative...")
        # Try a slight modification and repeat
        mod_target = bytearray(target_encryption)
        mod_target[0] ^= 1  # Flip one bit
        new_block = cipher_dec.decrypt(bytes(mod_target))
    
    return new_block

def create_second_preimage(original_data):
    # Get a colliding first block
    new_first_block = find_collision_block()
    
    # Keep rest of the blocks the same
    new_data = new_first_block + original_data[16:]
    
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
            print(f"Encrypted: {encrypted.hex()}")
            print(f"H{i+1}: {Hi.hex()}")
    
    print_hash_chain(original_data, "Original")
    print_hash_chain(new_data, "Modified")

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Don't write file if hashes don't match
    orig_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    print("\nFirst blocks comparison:")
    print(f"Original: {original_data[:16].hex()}")
    print(f"New:      {new_data[:16].hex()}")
    
    if orig_hash == new_hash and original_data != new_data:
        print("\nFound valid second preimage!")
        with open('snd.bin', 'wb') as f:
            f.write(new_data)
    else:
        print("\nNo valid collision found")
    
    verify_hashes(original_data, new_data)
    
    print("\nHash comparison:")
    print(f"Original: {orig_hash.hex()}")
    print(f"New:      {new_hash.hex()}")
    print(f"Target:   e758f7ce30186a937f073fd4ddab8393")

if __name__ == "__main__":
    main()