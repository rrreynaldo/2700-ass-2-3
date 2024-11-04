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
    
    # Step 2: Get H1 by encrypting first block
    cipher = AES.new(H0, AES.MODE_ECB)
    encrypted_block1 = cipher.encrypt(block1)
    H1 = strxor(encrypted_block1, long_to_bytes(1, AES.block_size))
    print(f"H1: {H1.hex()}")
    
    # Step 3: Get original H2 from fst.bin
    original_blocks = [original_data[i:i+16] for i in range(0, len(original_data), 16)]
    Hi = H0
    for i in range(2):
        x = original_blocks[i]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    H2_target = Hi
    print(f"Target H2: {H2_target.hex()}")
    
    # Step 4: Work backwards to find block2
    # H2_target = E_{H1}(block2) ⊕ 2
    # Therefore: E_{H1}(block2) = H2_target ⊕ 2
    target_encryption = strxor(H2_target, long_to_bytes(2, AES.block_size))
    print(f"Target encryption for block2: {target_encryption.hex()}")
    
    # Decrypt to get block2
    cipher = AES.new(H1, AES.MODE_ECB)
    block2 = cipher.decrypt(target_encryption)
    print(f"Generated block2: {block2.hex()}")
    
    # Step 5: Use original third block
    block3 = original_data[32:48]
    print(f"Block3: {block3.hex()}")
    
    # Combine blocks
    new_data = block1 + block2 + block3
    
    # Verify H2 is correct
    cipher = AES.new(H1, AES.MODE_ECB)
    test_H2 = strxor(cipher.encrypt(block2), long_to_bytes(2, AES.block_size))
    print(f"\nVerification:")
    print(f"Expected H2: {H2_target.hex()}")
    print(f"Actual H2:   {test_H2.hex()}")
    
    return new_data

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
    print(f"Length check: original={len(original_data)}, new={len(new_data)}")
    print(f"\nHash comparison:")
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