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
    
    # Take first block and ensure it's padded properly
    x = original_msg[:block_size-1]  # Take 15 bytes
    padded_x = pad(x, block_size)    # This will add 1 byte of padding
    
    # Calculate second block following the formula but using padded x
    second_block = strxor(strxor(padded_x, mac_bytes), IV)
    
    # Create forged message using unpadded first part
    forged_input = x + second_block
    
    print("\nDetailed Attack Analysis:")
    print("Original first part (15 bytes) hex:", x.hex())
    print("Padded first block (16 bytes) hex:", padded_x.hex())
    print("Known MAC m (hex):", mac)
    print("IV (hex):", IV.hex())
    print("XOR Steps:")
    print("1. padded_x ⊕ mac:", strxor(padded_x, mac_bytes).hex())
    print("2. (padded_x ⊕ mac) ⊕ IV = second block:", second_block.hex())
    
    print("\nForged Message Structure:")
    print("First part length (should be 15):", len(x))
    print("Second block length (should be 16):", len(second_block))
    print("Total length:", len(forged_input))
    print("Complete message (hex):", forged_input.hex())
    
    print("\nPadding Analysis:")
    final_padded = pad(forged_input, block_size)
    print("Length before final padding:", len(forged_input))
    print("Length after final padding:", len(final_padded))
    print("Final padded hex:", final_padded.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"./cbcmac_oracle snd.bin {mac}")

if __name__ == "__main__":
    create_forged_file()