from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Our known values
    TARGET_MAC = "6983ed2550f04de595951aabed20d7b1"  # MAC we saw from known key
    IV = b'fedcba9876543210'
    block_size = AES.block_size
    
    # Read original message
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    
    # Convert target MAC to bytes
    mac_bytes = binascii.unhexlify(TARGET_MAC)
    
    print("\nOriginal Message Analysis:")
    print("Length:", len(original_msg))
    print("First 16 bytes:", original_msg[:16].hex())
    print("Target MAC:", TARGET_MAC)
    
    # Take first block as our x
    x = original_msg[:block_size]
    
    # Following the attack slides: x' = x || (x ⊕ m ⊕ IV)
    xor1 = strxor(x, mac_bytes)
    second_block = strxor(xor1, IV)
    
    # Create forged message
    forged_input = x + second_block
    
    print("\nForged Message Construction:")
    print("First block (x):", x.hex())
    print("XOR1 (x ⊕ MAC):", xor1.hex())
    print("Second block (x ⊕ MAC ⊕ IV):", second_block.hex())
    print("Complete forged message:", forged_input.hex())
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify by running:")
    print('python3 cbcmac.py "1234567890123456" snd.bin')
    print(f"Should see MAC: {TARGET_MAC}")

if __name__ == "__main__":
    create_forged_file()