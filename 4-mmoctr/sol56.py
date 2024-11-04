from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

H0 = b'0123456789abcdef'

def print_bytes_hex(name, data):
    print(f"{name} (len={len(data)}):")
    print(' '.join(f'{b:02x}' for b in data))
    print()

def mmoctr(data, debug=False):
    if debug:
        print_bytes_hex("Initial data", data)
    
    data = pad(data, AES.block_size)
    if debug:
        print_bytes_hex("Padded data", data)
    
    k = len(data)//AES.block_size
    Hi = H0
    
    if debug:
        print(f"Number of blocks: {k}")
        print_bytes_hex("Initial H0", Hi)
    
    for i in range(k):
        x = data[i*16:(i+1)*16]
        if debug:
            print(f"\nProcessing block {i+1}:")
            print_bytes_hex(f"Block {i+1}", x)
            print_bytes_hex(f"Current H{i}", Hi)
        
        cipher = AES.new(Hi, AES.MODE_ECB)
        encrypted = cipher.encrypt(x)
        if debug:
            print_bytes_hex(f"Encrypted block {i+1}", encrypted)
            print_bytes_hex(f"Counter {i+1}", long_to_bytes(i+1, AES.block_size))
        
        Hi = strxor(encrypted, long_to_bytes(i+1, AES.block_size))
        if debug:
            print_bytes_hex(f"H{i+1} after XOR", Hi)
    
    return Hi

def debug_hash_chain(data):
    """Print detailed analysis of hash chain"""
    padded = pad(data, AES.block_size)
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    
    print("\nDetailed Hash Chain Analysis:")
    print("=============================")
    Hi = H0
    for i, block in enumerate(blocks):
        print(f"\nBlock {i+1}:")
        print_bytes_hex("Input block", block)
        print_bytes_hex("Current H", Hi)
        
        cipher = AES.new(Hi, AES.MODE_ECB)
        encrypted = cipher.encrypt(block)
        print_bytes_hex("After encryption", encrypted)
        
        counter = long_to_bytes(i+1, AES.block_size)
        print_bytes_hex(f"Counter ({i+1})", counter)
        
        Hi = strxor(encrypted, counter)
        print_bytes_hex("After XOR with counter", Hi)

def create_second_preimage(original_data):
    print("\nAnalyzing original data:")
    debug_hash_chain(original_data)
    
    # Calculate target intermediate values
    target_hash = bytes.fromhex('e758f7ce30186a937f073fd4ddab8393')
    print("\nTarget final hash:", target_hash.hex())
    
    # Create modified version
    new_data = bytearray(original_data)
    
    # Let's try modifying each byte of the last block before padding
    test_modifications = []
    for pos in range(max(0, len(new_data) - 16), len(new_data)):
        for bit in range(8):
            test_data = bytearray(new_data)
            test_data[pos] ^= (1 << bit)  # Flip each bit
            test_hash = mmoctr(bytes(test_data))
            test_modifications.append((test_hash.hex(), pos, bit, bytes(test_data)))
            print(f"\nTesting modification at pos {pos}, bit {bit}:")
            print(f"Modified byte: {test_data[pos]:02x} (original: {new_data[pos]:02x})")
            print(f"Resulting hash: {test_hash.hex()}")
    
    # Sort by how close the hash is to target
    test_modifications.sort(key=lambda x: sum(a != b for a, b in zip(bytes.fromhex(x[0]), target_hash)))
    
    # Use the best modification
    best_mod = test_modifications[0]
    print(f"\nBest modification found:")
    print(f"Position: {best_mod[1]}, Bit: {best_mod[2]}")
    print(f"Resulting hash: {best_mod[0]}")
    
    return best_mod[3]

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    print("Original data analysis:")
    original_hash = mmoctr(original_data, debug=True)
    print(f"\nOriginal hash: {original_hash.hex()}")
    
    new_data = create_second_preimage(original_data)
    new_hash = mmoctr(new_data)
    
    print("\nResults:")
    print(f"Original hash: {original_hash.hex()}")
    print(f"New hash:      {new_hash.hex()}")
    print(f"Target hash:   e758f7ce30186a937f073fd4ddab8393")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("\nSecond preimage has been written to snd.bin")

if __name__ == "__main__":
    main()