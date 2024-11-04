from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
import binascii

# Constants
IV = b'fedcba9876543210'
BLOCK_SIZE = AES.block_size

# Read the original message
with open('fst.bin', 'rb') as f:
    original_msg = f.read()

# Read the known MAC
with open('mac1.txt', 'r') as f:
    known_mac = binascii.unhexlify(f.read().strip())

# Step 1: Get the padded first message
padded_msg = pad(original_msg, BLOCK_SIZE)

# Step 2: Create second block
# In CBC-MAC, the second block should be: x ⊕ m ⊕ IV
# where x is the last block of padded message
last_block = padded_msg[-BLOCK_SIZE:]
second_block = strxor(strxor(last_block, known_mac), IV)

# Step 3: Create the new message
# New message = original_padded || second_block
new_msg = padded_msg + second_block

# Write the new message to snd.bin
with open('snd.bin', 'wb') as f:
    f.write(new_msg)

print(f"Original message length: {len(original_msg)}")
print(f"Padded message length: {len(padded_msg)}")
print(f"New message length: {len(new_msg)}")
print(f"MAC to use: {binascii.hexlify(known_mac).decode()}")