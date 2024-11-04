if __name__ == "__main__":
    # Open the binary file in read mode
    with open("snd.bin", 'rb') as file:
        # Read the file's content
        byte_data = file.read()

        # Print each byte in hexadecimal format
        for byte in byte_data:
            print(f"{byte:02x}", end=" ")
