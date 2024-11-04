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

def find_block3(target_hash):
    # We know:
    # 1. First two blocks are fixed, giving us H2
    # 2. Padding block is fixed (16 bytes of 0x10)
    # 3. target_hash = E_{H3}(padding) ⊕ 4
    
    # First get H2 by processing first two blocks
    original_blocks = [
        bytes.fromhex('a4048d07f516b94a43aa3d8f4ddc341a'),
        bytes.fromhex('12cf4a8b315e3db7518fe6d355899a28')
    ]
    
    Hi = H0
    for i, block in enumerate(original_blocks):
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(block), long_to_bytes(i+1, AES.block_size))
    H2 = Hi
    
    # Now we know:
    # H3 = E_{H2}(block3) ⊕ 3
    # target_hash = E_{H3}(padding) ⊕ 4
    
    # Work backwards:
    # Remove counter XOR from target hash
    target_before_counter = strxor(target_hash, long_to_bytes(4, AES.block_size))
    
    # This should be the encryption of the padding block with H3
    padding_block = bytes([0x10] * 16)
    
    # Try variations of block3
    original_block3 = bytes.fromhex('c819757e1f6041a5bfd72d8a82c2bb1c')
    for i in range(256):
        test_block3 = bytearray(original_block3)
        test_block3[-1] = i
        
        # Calculate H3 with this block3
        cipher = AES.new(H2, AES.MODE_ECB)
        H3 = strxor(cipher.encrypt(test_block3), long_to_bytes(3, AES.block_size))
        
        # Test if this H3 gives us our target
        cipher = AES.new(H3, AES.MODE_ECB)
        test_hash = strxor(cipher.encrypt(padding_block), long_to_bytes(4, AES.block_size))
        
        if test_hash == target_hash:
            return bytes(test_block3)
    
    return None

def create_second_preimage(original_data):
    target_hash = bytes.fromhex('e758f7ce30186a937f073fd4ddab8393')
    
    # Keep first 32 bytes (2 blocks) unchanged
    new_data = bytearray(original_data[:32])
    
    # Find the right block3
    block3 = find_block3(target_hash)
    if block3:
        new_data.extend(block3)
    
    return bytes(new_data)

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
            print(f"H{i+1}: {Hi.hex()}")
            print(f"Block {i+1}: {block.hex()}")
    
    print_hash_chain(original_data, "Original")
    print_hash_chain(new_data, "Modified")

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    verify_hashes(original_data, new_data)
    
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("\nSecond preimage has been written to snd.bin")
    print(f"Original hash: {mmoctr(original_data).hex()}")
    print(f"New hash: {mmoctr(new_data).hex()}")
    print(f"Target hash:  e758f7ce30186a937f073fd4ddab8393")

if __name__ == "__main__":
    main()