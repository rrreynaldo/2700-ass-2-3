from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def debug_xor(a, b, label):
    """Helper to print XOR operations"""
    result = strxor(a, b)
    print(f"\n{label}:")
    print(f"Input 1 (hex): {a.hex()}")
    print(f"Input 2 (hex): {b.hex()}")
    print(f"Result  (hex): {result.hex()}")
    return result

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
    
    print("\nInitial Data:")
    print("Original message length:", len(original_msg))
    print("Original message (hex):", original_msg.hex())
    print("Target MAC (hex):", mac)
    print("IV (hex):", IV.hex())
    
    # Take first complete block
    x = original_msg[:block_size]
    print("\nBlock Operations:")
    print("First block x (hex):", x.hex())
    
    # Calculate XORs step by step
    temp1 = debug_xor(x, mac_bytes, "Step 1: x ⊕ m")
    second_block = debug_xor(temp1, IV, "Step 2: (x ⊕ m) ⊕ IV")
    
    # Create forged message
    forged_input = x + second_block
    
    print("\nFinal Message Details:")
    print("Length:", len(forged_input))
    print("Full message (hex):", forged_input.hex())
    
    # Test padding
    test_pad = pad(forged_input, block_size)
    print("\nPadding Test:")
    print("Before padding length:", len(forged_input))
    print("After padding length:", len(test_pad))
    print("Padded message (hex):", test_pad.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()