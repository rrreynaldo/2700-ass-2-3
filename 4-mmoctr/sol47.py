from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

# Define constants
H0 = b'0123456789abcdef'  # Initial hash value
arb = b'\x00' * 16         # Arbitrary block of all zeros

# Given h2 value from your example
h2 = "7416495d81aaa2b25007e79bc09852e5"
h2b = bytes.fromhex(h2)  # Convert h2 hex string to bytes

# Compute first hash block H1
cipher = AES.new(H0, AES.MODE_ECB)
H1b = strxor(cipher.encrypt(arb), long_to_bytes(1, AES.block_size))  # Counter starts at 1

# Compute second hash block H2
cipher1 = AES.new(H1b, AES.MODE_ECB)
H2b = strxor(cipher1.encrypt(h2b), long_to_bytes(2, AES.block_size))  # Counter incremented to 2

# Decrypt to get the second block content that matches the original hash
decrypt = cipher1.decrypt(H2b)  # This is the second block that, when encrypted, produces H2b

# Construct the input for snd.bin
# The input will consist of:
# - First block: 16 bytes of all zeros (arb)
# - Second block: 'decrypt' to match the hash intermediate state
# - Third block: The last 16 bytes of fst.bin to match the final digest
with open("fst.bin", "rb") as f:
    fst_data = f.read()
snd_data = arb + decrypt + fst_data[32:48]  # Concatenate blocks to form snd.bin content

# Write snd_data to snd.bin
with open("snd.bin", "wb") as snd_file:
    snd_file.write(snd_data)
    
print("First hex: ", fst_data.hex())
print("Second hex: ", snd_data.hex())

print("Second-preimage created and saved as snd.bin.")
print("Run './mmoctr_oracle snd.bin' to check if the hash matches and retrieve the flag.")
