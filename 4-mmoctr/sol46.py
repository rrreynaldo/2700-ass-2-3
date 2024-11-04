import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

# Define the initial hash value (as given in the problem)
H0 = b'0123456789abcdef'

def mmoctr(data):
    """Hash function based on the flawed MMOCTR algorithm."""
    data = pad(data, AES.block_size)
    k = len(data) // AES.block_size
    Hi = H0
    for i in range(k):
        x = data[i*AES.block_size:(i+1)*AES.block_size]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    return Hi

# Read the contents of fst.bin
with open("fst.bin", "rb") as f:
    fst_data = f.read()

# Compute the original hash of fst.bin
original_hash = mmoctr(fst_data)
print("Original hash:", original_hash.hex())

# Try creating a second preimage by modifying one byte at a time
# (Here, you can extend the range or modify more bytes if needed for other tests)
for i in range(len(fst_data)):
    for j in range(256):  # Try all possible byte values (0-255)
        # Create a modified version of the data
        modified_data = bytearray(fst_data)
        modified_data[i] = j  # Change the i-th byte to j

        # Compute the hash of the modified data
        modified_hash = mmoctr(modified_data)

        # Check if the modified hash matches the original hash
        if modified_hash == original_hash:
            print("Match found!")
            print(f"Modified byte index: {i}, Byte value: {j}")

            # Save this modified data as snd.bin
            with open("snd.bin", "wb") as snd_file:
                snd_file.write(modified_data)

            print("Second preimage saved as snd.bin")
            break  # Exit inner loop if a match is found
    else:
        continue  # Continue to next byte position if no match found
    break  # Exit outer loop if a match is found

print("Process complete. Run './mmoctr_oracle snd.bin' to verify the flag.")
