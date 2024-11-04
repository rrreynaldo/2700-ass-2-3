from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad
import binascii

def read_first_file():
    """Read the content of fst.bin"""
    with open('fst.bin', 'rb') as f:
        return f.read()

def read_first_mac():
    """Read the MAC from mac1.txt"""
    with open('mac1.txt', 'r') as f:
        return f.read().strip()

def create_forged_file(original_content, original_mac):
    """Create a forged file and its MAC"""
    # Convert hex MAC to bytes
    mac_bytes = bytes.fromhex(original_mac)
    
    # Get the block size
    block_size = AES.block_size
    
    # Pad the original content
    padded_original = pad(original_content, block_size)
    
    # Create a new message that's different from the original
    # We'll use a two-block approach:
    # Block1 = original_padded
    # Block2 = carefully crafted block to cancel out the MAC
    
    # The new content will be the padded original followed by the MAC
    forged_content = padded_original + mac_bytes
    
    # The MAC of this new message will be the same as the original MAC
    # due to how CBC-MAC works with length extension
    
    # Save the forged content
    with open('snd.bin', 'wb') as f:
        f.write(forged_content)
    
    return forged_content, original_mac

def main():
    # Read original file and MAC
    original_content = read_first_file()
    original_mac = read_first_mac()
    
    print(f"Original content length: {len(original_content)} bytes")
    print(f"Original MAC: {original_mac}")
    
    # Create forged file and MAC
    forged_content, forged_mac = create_forged_file(original_content, original_mac)
    
    print(f"\nForged content length: {len(forged_content)} bytes")
    print(f"Forged MAC: {forged_mac}")
    print(f"\nForged content has been saved to snd.bin")
    print(f"To verify, run: ./cbcmac_oracle snd.bin {forged_mac}")

if __name__ == "__main__":
    main()