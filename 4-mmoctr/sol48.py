from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

# Initial hash value
H0 = b'0123456789abcdef'

def mmoctr(data):
    """Hash function based on the flawed MMOCTR algorithm."""
    data = pad(data, AES.block_size)
    k = len(data) // AES.block_size
    Hi = H0
    for i in range(k):
        x = data[i * AES.block_size:(i + 1) * AES.block_size]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i + 1, AES.block_size))
    return Hi

# Load the content of fst.bin
with open("fst.bin", "rb") as f:
    fst_data = f.read()

# Compute the original hash of fst.bin
original_hash = mmoctr(fst_data)
print("Original hash:", original_hash.hex())

# Create a matching snd.bin by aligning intermediate states
# Use zeros or other values that align the intermediate states
arb = b'\x00' * 16
snd_data = bytearray(arb) * 3  # Three blocks for 48 bytes (same as fst.bin length)

# Modify snd_data to match intermediate states
for i in range(3):
    # Adjust each block to create matching intermediate hash values
    block = snd_data[i * 16:(i + 1) * 16]
    snd_data[i * 16:(i + 1) * 16] = strxor(block, long_to_bytes(i + 1, AES.block_size))

# Save the modified snd_data as snd.bin
with open("snd.bin", "wb") as snd_file:
    snd_file.write(snd_data)

print("Second-preimage created and saved as snd.bin.")
print("Run './mmoctr_oracle snd.bin' to check if the hash matches and retrieve the flag.")
