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

def find_block_collision():
    # Original first block
    original_block = bytes.fromhex('a4048d07f516b94a43aa3d8f4ddc341a')
    
    # Get H1 for original block
    cipher = AES.new(H0, AES.MODE_ECB)
    original_encrypted = cipher.encrypt(original_block)
    H1 = strxor(original_encrypted, long_to_bytes(1, AES.block_size))
    
    print(f"Original block: {original_block.hex()}")
    print(f"Original encrypted: {original_encrypted.hex()}")
    print(f"Original H1: {H1.hex()}")
    
    # Key insight: For any new block x':
    # E_{H0}(x') ⊕ 1 = H1
    # Therefore: E_{H0}(x') = H1 ⊕ 1
    
    target_encryption = strxor(H1, long_to_bytes(1, AES.block_size))
    print(f"Target encryption: {target_encryption.hex()}")
    
    # Create a new block that's clearly different
    new_block = bytearray([x ^ 0xFF for x in original_block])  # Flip all bits
    cipher = AES.new(H0, AES.MODE_ECB)
    encrypted = cipher.encrypt(bytes(new_block))
    
    # Calculate what XOR value we need
    xor_value = strxor(encrypted, target_encryption)
    
    # Create final block by XORing with this value
    final_block = strxor(bytes(new_block), xor_value)
    
    print(f"New block: {final_block.hex()}")
    
    # Verify it works
    cipher = AES.new(H0, AES.MODE_ECB)
    final_encrypted = cipher.encrypt(final_block)
    final_H1 = strxor(final_encrypted, long_to_bytes(1, AES.block_size))
    
    print(f"New encrypted: {final_encrypted.hex()}")
    print(f"New H1: {final_H1.hex()}")
    
    return final_block

def create_second_preimage(original_data):
    new_first_block = find_block_collision()
    return new_first_block + original_data[16:]

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
            print(f"XOR with {i+1}: {long_to_bytes(i+1, AES.block_size).hex()}")
            print(f"H{i+1}: {Hi.hex()}")
            
    print_hash_chain(original_data, "Original")
    print_hash_chain(new_data, "Modified")

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    verify_hashes(original_data, new_data)
    
    # Compare hashes
    orig_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    print("\nResults:")
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