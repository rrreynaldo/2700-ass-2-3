from Crypto.Util.strxor import strxor
import binascii

def create_forged_file():
    # Fixed IV from implementation
    IV = b'fedcba9876543210'
    
    # Original message from fst.bin
    original_msg = b"gqJtVdlpcySTjfQHWkkoGddSbeWZNaUjzJUwEwGeOUyeWCRyfhYlSswSdjTxkvORGvxSioyvFBnDQNuaAIBYnx"
    
    # Known MAC (y in the formula)
    mac = "400b3f71959baf64ccfdb8f45d9246f3"
    mac_bytes = binascii.unhexlify(mac)
    
    # Calculate y ⊕ IV ⊕ x
    iv_xor_input = strxor(IV, original_msg)  # First XOR: IV ⊕ x
    mac_xor_result = strxor(mac_bytes, iv_xor_input)  # Second XOR: y ⊕ (IV ⊕ x)
    
    # Create forged input: x || (y ⊕ IV ⊕ x)
    forged_input = original_msg + mac_xor_result
    
    # Debug prints
    print("Original message (hex):", original_msg.hex())
    print("IV (hex):", IV.hex())
    print("MAC (hex):", mac)
    print("IV XOR input (hex):", iv_xor_input.hex())
    print("Final XOR result (hex):", mac_xor_result.hex())
    print("Forged input (hex):", forged_input.hex())
    
    # Write to snd.bin
    with open('snd.bin', 'wb') as f:
        f.write(forged_input)
    
    print("\nCreated snd.bin")
    print("Use MAC:", mac)

if __name__ == "__main__":
    create_forged_file()