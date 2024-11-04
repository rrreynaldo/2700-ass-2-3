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
    
    # Create forged content by appending MAC bytes to padded original
    forged_content = padded_original + mac_bytes
    
    # Save the forged content to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(forged_content)
    
    # Save detailed information about the contents
    with open('content_details.txt', 'w') as f:
        f.write("Original Content Analysis:\n")
        f.write(f"Length: {len(original_content)} bytes\n")
        f.write(f"Hex: {original_content.hex()}\n")
        f.write(f"ASCII: {original_content.decode('ascii', errors='replace')}\n\n")
        
        f.write("Padded Original Content:\n")
        f.write(f"Length: {len(padded_original)} bytes\n")
        f.write(f"Hex: {padded_original.hex()}\n")
        f.write(f"Last block (padding): {padded_original[-block_size:].hex()}\n\n")
        
        f.write("MAC as bytes:\n")
        f.write(f"Length: {len(mac_bytes)} bytes\n")
        f.write(f"Hex: {mac_bytes.hex()}\n\n")
        
        f.write("Forged Content:\n")
        f.write(f"Length: {len(forged_content)} bytes\n")
        f.write(f"Hex: {forged_content.hex()}\n")
        f.write(f"Difference from original: Added {len(forged_content) - len(original_content)} bytes\n")
    
    # Save MAC in binary format
    with open('forged_mac.bin', 'wb') as f:
        f.write(mac_bytes)
    
    return forged_content, original_mac

def main():
    # Read original file and MAC
    original_content = read_first_file()
    original_mac = read_first_mac()
    
    print("Original content:")
    print(f"Length: {len(original_content)} bytes")
    print(f"Content (hex): {original_content.hex()}")
    print(f"Content (ascii): {original_content.decode('ascii', errors='replace')}")
    print(f"MAC: {original_mac}")
    
    # Create forged file and MAC
    forged_content, forged_mac = create_forged_file(original_content, original_mac)
    
    print("\nForged content:")
    print(f"Length: {len(forged_content)} bytes")
    print(f"Content (hex): {forged_content.hex()}")
    print(f"Difference: Added {len(forged_content) - len(original_content)} bytes")
    print(f"MAC: {forged_mac}")
    
    print("\nFiles created:")
    print("- snd.bin: Contains the forged content")
    print("- forged_mac.bin: Contains the MAC in binary format")
    print("- content_details.txt: Detailed analysis of all contents")
    
    print(f"\nTo verify, run:")
    print(f"./cbcmac_oracle snd.bin {forged_mac}")

if __name__ == "__main__":
    main()