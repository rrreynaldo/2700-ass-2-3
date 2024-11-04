from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Fixed IV
    IV = b'fedcba9876543210'
    block_size = AES.block_size
    
    # Read original message and MAC
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Take first block of original message
    x = original_msg[:block_size]  # This is our known one-block message
    
    # Following the formula: x' = x || (x ⊕ m ⊕ IV)
    # where m is our known MAC
    second_block = strxor(strxor(x, mac_bytes), IV)
    
    # Create forged message x'
    forged_input = x + second_block
    
    print("\nAttack Analysis:")
    print("Step 1: One-block message x (hex):", x.hex())
    print("Step 2: Known MAC m (hex):", mac)
    print("Step 3: Known IV (hex):", IV.hex())
    print("Step 4: Calculated x ⊕ m (hex):", strxor(x, mac_bytes).hex())
    print("Step 5: Final (x ⊕ m ⊕ IV) (hex):", second_block.hex())
    print("\nForged Message Details:")
    print("Length:", len(forged_input))
    print("First block (x):", x.hex())
    print("Second block (x ⊕ m ⊕ IV):", second_block.hex())
    print("Complete forged message (hex):", forged_input.hex())
    
    # Additional debug information
    print("\nBlock Size Analysis:")
    print(f"Block size: {block_size}")
    print(f"Original message length: {len(original_msg)}")
    print(f"Forged message length: {len(forged_input)}")
    print(f"Is forged message multiple of block size: {len(forged_input) % block_size == 0}")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()