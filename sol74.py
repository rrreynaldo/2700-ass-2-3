from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

def create_forged_file():
    # Fixed IV
    IV = b'fedcba9876543210'
    block_size = AES.block_size
    
    # Read original message and target MAC
    with open('fst.bin', 'rb') as f:
        original_msg = f.read()
    TARGET_MAC = "6983ed2550f04de595951aabed20d7b1"
    m = binascii.unhexlify(TARGET_MAC)
    
    # Following the proof exactly:
    # 1. Let x1 = x (first block of message)
    x = original_msg[:block_size]
    
    # 2. Calculate x2 = x ⊕ m ⊕ IV
    # First XOR: x ⊕ m
    xor_x_m = strxor(x, m)
    # Then XOR with IV: (x ⊕ m) ⊕ IV
    x2 = strxor(xor_x_m, IV)
    
    print("\nAttack Construction Following Proof:")
    print(f"Step 1: x1 = x = {x.hex()}")
    print(f"Step 2: Calculate x2 = x ⊕ m ⊕ IV")
    print(f"   - x ⊕ m = {xor_x_m.hex()}")
    print(f"   - (x ⊕ m) ⊕ IV = {x2.hex()}")
    
    # 3. Construct x' = x1 || x2
    forged_input = x + x2
    
    print("\nFinal Construction:")
    print(f"x' = x1 || x2 = {forged_input.hex()}")
    
    # 4. According to proof:
    # MAC_k(x') = e_k(x2 ⊕ m) = e_k(x ⊕ m ⊕ IV ⊕ m) = e_k(x ⊕ IV) = m
    
    print("\nPadding Analysis:")
    padded = pad(forged_input, block_size)
    print(f"Original length: {len(forged_input)}")
    print(f"Padded length: {len(padded)}")
    print(f"Padded hex: {padded.hex()}")
    
    # Write forged message
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Verify with:")
    print(f"python3 cbcmac.py \"1234567890123456\" snd.bin")
    print(f"Expected MAC: {TARGET_MAC}")

if __name__ == "__main__":
    create_forged_file()