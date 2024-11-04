from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import binascii

def analyze_padding(data):
    # Original data length
    orig_len = len(data)
    # Padded length
    padded = pad(data, 16)
    padded_len = len(padded)
    
    print(f"Original length: {orig_len}")
    print(f"Padded length: {padded_len}")
    print(f"Padding bytes: {list(padded[-16:])}")
    
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    return blocks

# Read original file and MAC
with open('fst.bin', 'rb') as f:
    original_data = f.read()
    
mac = binascii.unhexlify('400b3f71959baf64ccfdb8f45d9246f3')
iv = b'fedcba9876543210'

# Analyze padding of original file
blocks = analyze_padding(original_data)

# Calculate what the last block would be after padding
last_block = blocks[-1]
print("\nLast block (hex):", binascii.hexlify(last_block).decode())
print("MAC (hex):", binascii.hexlify(mac).decode())

# Calculate potential extension block
extension = strxor(strxor(last_block, mac), iv)
print("\nPotential extension block (hex):", binascii.hexlify(extension).decode())