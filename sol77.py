from Crypto.Util.strxor import strxor
import binascii

# Original data from fst.bin
with open('fst.bin', 'rb') as f:
    input_data = f.read()

# Known values
IV = b'fedcba9876543210'
mac = binascii.unhexlify('400b3f71959baf64ccfdb8f45d9246f3')

# Following the exact pattern from Exercise 6:
# x' = x || (y ⊕ IV ⊕ x) where y is the MAC
fake_input = input_data + strxor(mac, strxor(IV, input_data))

# Write to snd.bin
with open('snd.bin', 'wb') as f:
    f.write(fake_input)

print("Original length:", len(input_data))
print("Forged message length:", len(fake_input))
print("MAC to use:", mac.hex())
print("\nForged message saved to snd.bin")

# For verification/debugging
print("\nForged message components:")
print("Original message:", input_data[:16].hex())  # Show first block
print("Extension block:", strxor(mac, strxor(IV, input_data[:16])).hex())