if __name__ == "__main__":
    # Opening the file in read binary mode to count the number of bytes
    with open("fst.bin", 'rb') as file:
        byte_data = file.read()  # read the entire content
        byte_count = len(byte_data)  # count the number of bytes

    print(f"Number of bytes in the file: {byte_count}")