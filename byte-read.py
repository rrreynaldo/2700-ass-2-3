import binascii

if __name__ == "__main__":
    # Opening the file in read binary mode to count the number of bytes
    with open("fst.bin", 'rb') as file:
        byte_data = file.read()  # read the entire content
        byte_count = len(byte_data)  # count the number of bytes

    print(f"Number of bytes in the fst.bin file: {byte_count}")
    
    # Opening the file in read binary mode to count the number of bytes
    with open("snd.bin", 'rb') as file:
        byte_data = file.read()  # read the entire content
        byte_count = len(byte_data)  # count the number of bytes

    print(f"Number of bytes in the snd.bin file: {byte_count}")
    
    # Opening the file in read binary mode to count the number of bytes
    with open("mac1.txt", 'rb') as file:
        byte_data = file.read()  # read the entire content
        byte_count = len(byte_data)  # count the number of bytes

    print(f"Number of bytes in the mac1.txt file: {byte_count}")
    
    # Read and convert the MAC from hex to bytes
    with open('mac1.txt', 'r') as f:
        mac_hex = f.read().strip()  # "400b3f71959baf64ccfdb8f45d9246f3"
        # Convert hex string to bytes:
        mac_bytes = binascii.unhexlify(mac_hex)  # This gives us 16 bytes
        print(f"MAC hex length: {len(mac_hex)} characters")  # Should be 32
        print(f"MAC bytes length: {len(mac_bytes)} bytes")   # Should be 16
    
    # Open the binary file in read mode
    with open("mac1.txt", 'rb') as file:
        # Read the file's content
        byte_data = file.read()

        # Print each byte in hexadecimal format
        for byte in byte_data:
            print(f"{byte:02x}", end=" ")
    
    # Open the binary file in read mode
    with open("snd.bin", 'rb') as file:
        # Read the file's content
        byte_data = file.read()

        # Print each byte in hexadecimal format
        for byte in byte_data:
            print(f"{byte:02x}", end=" ")