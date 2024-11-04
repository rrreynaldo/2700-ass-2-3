from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original message
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    
    # Read MAC from file
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Fixed IV from implementation
    IV = b'fedcba9876543210'
    
    # Create a simple one-block message
    x = b"A" * 16  # Single block of 'A's
    
    # Calculate y ⊕ IV ⊕ x
    xor_iv_x = strxor(IV, x)
    second_block = strxor(mac_bytes, xor_iv_x)
    
    # Create forged input: x || (y ⊕ IV ⊕ x)
    forged_input = x + second_block
    
    print("\nDetailed Analysis:")
    print("Simple block x (hex):", x.hex())
    print("IV (hex):", IV.hex())
    print("MAC (hex):", mac)
    print("IV XOR x (hex):", xor_iv_x.hex())
    print("Second block (hex):", second_block.hex())
    print("Forged input length:", len(forged_input))
    print("Forged input (hex):", forged_input.hex())
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Use this command to verify:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()