from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Fixed IV from implementation
    IV = b'fedcba9876543210'
    
    # Read MAC from file
    with open('mac1.txt', 'r') as f:
        mac = f.read().strip()
    mac_bytes = binascii.unhexlify(mac)
    
    # Create first block that will cause specific padding
    # We want a message that will get padded to exactly two blocks
    # AES block size is 16, so let's create a message of length 17
    x = b"A" * 17  # This will force padding to fill up to 32 bytes
    
    # Calculate padding that will be applied
    padded_x = pad(x[:16], AES.block_size)  # Pad the first block
    
    # XOR operations
    xor_iv_padded = strxor(IV, padded_x)
    second_block = strxor(mac_bytes, xor_iv_padded)
    
    # Create forged message: first block + second block
    forged_input = x[:16] + second_block
    
    print("\nDetailed Analysis:")
    print("Original message length:", len(x))
    print("First block (hex):", x[:16].hex())
    print("Padded first block (hex):", padded_x.hex())
    print("IV (hex):", IV.hex())
    print("MAC from file (hex):", mac)
    print("IV XOR padded (hex):", xor_iv_padded.hex())
    print("Second block (hex):", second_block.hex())
    print("Final message length:", len(forged_input))
    print("Final message (hex):", forged_input.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()