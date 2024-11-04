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
    
    # Open the binary file in read mode
    with open("snd.bin", 'rb') as file:
        # Read the file's content
        byte_data = file.read()

        # Print each byte in hexadecimal format
        for byte in byte_data:
            print(f"{byte:02x}", end=" ")