from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Read original message
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    print("Raw fst.bin content (hex):", original_msg.hex())
    
    # Read MAC from file with detailed debugging
    with open('mac1.txt', 'r') as f:
        mac_raw = f.read()
    print("\nRaw mac1.txt content:", repr(mac_raw))
    mac = mac_raw.strip()
    print("Stripped MAC:", mac)
    print("MAC length:", len(mac))
    mac_bytes = binascii.unhexlify(mac)
    print("MAC bytes (hex):", mac_bytes.hex())
    
    # Fixed IV from implementation
    IV = b'fedcba9876543210'
    
    # Pad the original message to block size
    block_size = AES.block_size
    padded_msg = pad(original_msg, block_size)
    
    # Take just the first block of padded message
    first_block = padded_msg[:block_size]
    
    print("\nDetailed block analysis:")
    print(f"Block size: {block_size}")
    print(f"Original message length: {len(original_msg)}")
    print(f"Padded message length: {len(padded_msg)}")
    print(f"First block length: {len(first_block)}")
    
    # Calculate y ⊕ IV ⊕ x
    iv_xor_input = strxor(IV, first_block)  # First XOR: IV ⊕ x
    second_block = strxor(mac_bytes, iv_xor_input)  # Second XOR: y ⊕ (IV ⊕ x)
    
    # Create forged input: x || (y ⊕ IV ⊕ x)
    forged_input = first_block + second_block
    
    print("\nXOR Operation Details:")
    print("First block (hex):", first_block.hex())
    print("IV (hex):", IV.hex())
    print("IV XOR first_block (hex):", iv_xor_input.hex())
    print("Second block (hex):", second_block.hex())
    
    print("\nFinal Output:")
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