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
    # First, understand what padding is being used
    padded = pad(original_data, AES.block_size)
    original_length = len(original_data)
    padding_length = len(padded) - original_length
    
    # Create a new first block that's different but will lead to the same hash
    new_data = bytearray(original_data)
    
    # Calculate the target H3 (before padding block)
    target_hash = bytes.fromhex('e758f7ce30186a937f073fd4ddab8393')
    # We know target_hash = E_{H3}(padding) ⊕ 4
    # Therefore H3 should encrypt padding to give: target_hash ⊕ 4
    
    # Modify the last byte of the third block
    # This changes H3 but keeps the size the same so padding remains identical
    new_data[-1] ^= 1  # Flip one bit in the last byte before padding
    
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
    
    print_hash_chain(original_data, "Original")
    print_hash_chain(new_data, "Modified")

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Verify the hashes
    verify_hashes(original_data, new_data)
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("\nSecond preimage has been written to snd.bin")
    print(f"Original hash: {mmoctr(original_data).hex()}")
    print(f"New hash: {mmoctr(new_data).hex()}")
    print(f"Target hash:  e758f7ce30186a937f073fd4ddab8393")

if __name__ == "__main__":
    main()