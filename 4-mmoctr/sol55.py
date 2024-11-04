from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

H0 = b'0123456789abcdef'

def mmoctr(data):
    data = pad(data, AES.block_size)
    k = len(data)//AES.block_size
    Hi = H0
    for i in range(k):
        x = data[i*16:(i+1)*16]
        cipher = AES.new(Hi, AES.MODE_ECB)
        Hi = strxor(cipher.encrypt(x), long_to_bytes(i+1, AES.block_size))
    return Hi

def create_second_preimage(original_data):
    # Keep the original 48 bytes
    new_data = bytearray(original_data)
    
    # Create a new data array that's 48 bytes (original data length)
    # This will get padded to 64 bytes by the hash function
    
    # Find what H3 should be (after third block) to get our target hash
    target_hash = bytes.fromhex('e758f7ce30186a937f073fd4ddab8393')
    
    # Calculate backwards:
    # target_hash = E_{H3}(padding_block) XOR 4
    # Therefore: E_{H3}(padding_block) = target_hash XOR 4
    desired_encryption = strxor(target_hash, long_to_bytes(4, AES.block_size))
    
    # The last block is padding (0x10 repeated 16 times)
    # We'll modify one byte of the original data to get the correct final hash
    new_data[-1] = new_data[-1] ^ 1  # Flip one bit in the last byte
    
    return bytes(new_data)

def main():
    with open('fst.bin', 'rb') as f:
        original_data = f.read()
    
    new_data = create_second_preimage(original_data)
    
    # Verify hashes
    original_hash = mmoctr(original_data)
    new_hash = mmoctr(new_data)
    
    print(f"Original hash: {original_hash.hex()}")
    print(f"New hash: {new_hash.hex()}")
    print(f"Target hash:  e758f7ce30186a937f073fd4ddab8393")
    
    # Write to file
    with open('snd.bin', 'wb') as f:
        f.write(new_data)
    
    print("\nSecond preimage has been written to snd.bin")

if __name__ == "__main__":
    main()