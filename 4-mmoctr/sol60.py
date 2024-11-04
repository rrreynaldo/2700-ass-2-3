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

def find_first_block_collision():
    # Original first block
    original_block = bytes.fromhex('a4048d07f516b94a43aa3d8f4ddc341a')
    
    # Get its encryption
    cipher = AES.new(H0, AES.MODE_ECB)
    target_encrypted = cipher.encrypt(original_block)
    
    print(f"Target encrypted value: {target_encrypted.hex()}")
    
    # Let's try to find another block that encrypts to exactly this value
    # We'll modify our approach to the decryption
    cipher_dec = AES.new(H0, AES.MODE_ECB)
    
    # Try a few different modifications to the encrypted value
    # that should give us the same XOR result
    test_blocks = []
    
    # Generate test blocks by modifying the original block
    for byte_pos in range(16):
        for bit_pos in range(8):
            modified = bytearray(original_block)
            modified[byte_pos] ^= (1 << bit_pos)
            
            # Check if this modification gives us what we want
            cipher = AES.new(H0, AES.MODE_ECB)
            encrypted = cipher.encrypt(bytes(modified))
            
            if encrypted == target_encrypted and bytes(modified) != original_block:
                print(f"Found collision! Position {byte_pos}, bit {bit_pos}")
                return bytes(modified)
            
            # Also try double bit flips at opposite ends
            if byte_pos < 8:  # Only do this for first half
                modified2 = bytearray(modified)
                modified2[15-byte_pos] ^= (1 << bit_pos)  # Flip corresponding bit at other end
                
                encrypted = cipher.encrypt(bytes(modified2))
                if encrypted == target_encrypted and bytes(modified2) != original_block:
                    print(f"Found collision with double flip!")
                    return bytes(modified2)
    
    return None

def create_second_preimage(original_data):
    # Find a colliding first block
    new_first_block = find_first_block_collision()
    if new_first_block is None:
        print("Failed to find collision")
        return original_data
    
    # Keep the rest of the blocks the same
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
            print(f"Counter {i+1}: {long_to_bytes(i+1, AES.block_size).hex()}")
            print(f"H{i+1}: {Hi.hex()}")
    
    print_hash_chain(original_data, "Original")
    print_hash_chain(new_data, "Modified")

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Compare first blocks
    print("\nFirst blocks comparison:")
    print(f"Original: {original_data[:16].hex()}")
    print(f"New:      {new_data[:16].hex()}")
    
    # Verify both produce same hash
    orig_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    if orig_hash == new_hash and original_data != new_data:
        print("\nFound valid second preimage!")
        with open('snd.bin', 'wb') as f:
            f.write(new_data)
    
    print("\nHash comparison:")
    print(f"Original: {orig_hash.hex()}")
    print(f"New:      {new_hash.hex()}")
    print(f"Target:   e758f7ce30186a937f073fd4ddab8393")

if __name__ == "__main__":
    main()