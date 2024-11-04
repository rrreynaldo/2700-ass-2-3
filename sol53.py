from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

def create_forged_file():
    # Known MAC from fst.bin (this acts as our "encrypted block")
    known_mac = "400b3f71959baf64ccfdb8f45d9246f3"
    mac_bytes = binascii.unhexlify(known_mac)
    
    # Fixed IV from the CBC-MAC implementation
    IV = b'fedcba9876543210'
    
    # Create a different message that's one block size
    # We'll use a different content than fst.bin
    new_content = b"This is a different message than the original!"
    padded_content = pad(new_content, AES.block_size)
    
    # Combine the original MAC (acting as IV for the second part)
    # with our new content to create snd.bin
    forged_content = mac_bytes + padded_content
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(forged_content)
    
    print("Created snd.bin with forged content")
    print("Use MAC:", known_mac)
    print("The oracle should accept this MAC for the new file")

if __name__ == "__main__":
    create_forged_file()