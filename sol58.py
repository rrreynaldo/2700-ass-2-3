from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original message and MAC
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Fixed IV
    IV = b'fedcba9876543210'
    
    # Create first message block
    # We'll use a message that will create interesting padding
    x = b"X" * (AES.block_size - 1)  # 15 bytes
    
    # Calculate padding for this block
    padded_x = pad(x, AES.block_size)
    
    # XOR operations for second block
    xor_iv_padded = strxor(IV, padded_x)
    second_block = strxor(mac_bytes, xor_iv_padded)
    
    # Create forged message
    forged_input = x + second_block  # Note: No padding here
    
    print("\nAnalysis:")
    print("Original x length:", len(x))
    print("Padded x (hex):", padded_x.hex())
    print("IV (hex):", IV.hex())
    print("MAC (hex):", mac)
    print("IV XOR padded_x (hex):", xor_iv_padded.hex())
    print("Second block (hex):", second_block.hex())
    print("Final forged input length:", len(forged_input))
    print("Forged input (hex):", forged_input.hex())
    
    # Write forged file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()