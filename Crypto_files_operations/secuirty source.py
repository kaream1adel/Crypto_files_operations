from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
def encrypt_file_aes(input_file, output_file,key):

    # Generate a random initialization vector (IV)

    iv = get_random_bytes(AES.block_size)
    
    # Create an AES cipher object with the generated key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Write the IV to the output file
        outfile.write(iv)

        # Read and encrypt the file in chunks
        chunk_size = 16 * 1024
        while True:
            chunk = infile.read(chunk_size)
            if not chunk:
                break
            # Pad the last chunk before encryption
            if len(chunk) % AES.block_size != 0:
                chunk = pad(chunk, AES.block_size)
            # Encrypt the chunk and write to the output file
            encrypted_chunk = cipher.encrypt(chunk)
            outfile.write(encrypted_chunk)
            

    print(f'Encryption complete. Output file: {output_file}')
    print(f'Generated key: {key.hex()}')

def decrypt_file_aes(encrypted_file, decrypted_file, key):
    # Read the IV from the encrypted file
    with open(encrypted_file, 'rb') as infile:
        iv = infile.read(AES.block_size)

    # Create an AES cipher object with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(encrypted_file, 'rb') as infile, open(decrypted_file, 'wb') as outfile:
        # Skip the IV in the input file
        infile.seek(AES.block_size)

        # Read and decrypt the file in chunks
        chunk_size = 16 * 1024
        while True:
            chunk = infile.read(chunk_size)
            if not chunk:
                break
            # Decrypt the chunk and write to the output file
            decrypted_chunk = cipher.decrypt(chunk)
            # Unpad the last chunk after decryption
            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
            outfile.write(decrypted_chunk)

    print(f'Decryption complete. Output file: {decrypted_file}')

def RSA_generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key

def RSA_save_key_to_file(key, filename): #save the key to a file for debug
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def RSA_load_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
        key = RSA.import_key(key_data)
        return key

def RSA_encrypt_file(input_filename, output_filename, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)

    with open(input_filename, 'rb') as infile, open(output_filename, 'wb') as outfile:
        plaintext = infile.read()
        ciphertext = cipher.encrypt(plaintext)
        outfile.write(base64.b64encode(ciphertext))

def RSA_decrypt_file(input_filename, output_filename, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)

    with open(input_filename, 'rb') as infile, open(output_filename, 'wb') as outfile:
        ciphertext = base64.b64decode(infile.read())
        decrypted_text = cipher.decrypt(ciphertext)
        outfile.write(decrypted_text)

def RSA_sign_data(input_file, output_file, private_key):         # produce signature using hash and private key
    with open(input_file, 'rb') as file:
       data = file.read()
    key = RSA.import_key(private_key)
    h = SHA512.new(data)
    signature = pkcs1_15.new(key).sign(h)
    with open(output_file, 'wb') as output_file:
        output_file.write(signature)

def RSA_verify_signature(input_file, signature, public_key):
    
       # Open the input file and read the data
    with open(input_file, 'rb') as file:
       data = file.read()
         # verify signature using hash and public key
    key = RSA.import_key(public_key)
    h = SHA512.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True  # Signature is valid
    except (ValueError, TypeError):
        return False  # Signature is invalid    

def RSA_sign_and_encrypt(input_file, output_file, private_key, aes_key):
    # Read plaintext data from the input file
    with open(input_file, 'rb') as infile:
        plaintext = infile.read()

    # Sign the plaintext using RSA with SHA-512
    RSA_sign_data(input_file, output_file, private_key)

    with open(output_file, 'rb') as signfile:
        signature = signfile.read()

    # Append the plaintext to the signature
    signed_data = signature + plaintext

    signed_file = 'signed_data.tmp'
    with open(signed_file, 'wb') as signed_file_out:
        signed_file_out.write(signed_data)

    # Encrypt the signed data using your AES encryption function
    encrypt_file_aes(signed_file, output_file, aes_key)

def RSA_decrypt_and_verify_data(input_file, output_file, public_key, aes_key): 
 
    # Decrypt the combined data using your AES decryption function
    decrypt_file_aes(input_file, output_file, aes_key)
    with open(output_file, 'rb') as outfile:
        decrypted_data = outfile.read()  
     

    # Extract the signature and original plaintext
    signature = decrypted_data[:256]  # Assuming a 2048-bit RSA key, 256 bytes for the signature
    plaintext = decrypted_data[256:]

    with open(output_file, 'wb') as outfile:
        outfile.write(plaintext)

    data_file = 'data.tmp'
    with open(data_file, 'wb') as data_out:
        data_out.write(plaintext)

    # Verify the signature using RSA with SHA-512
    verification_result = RSA_verify_signature(data_file, signature, public_key)

    return  verification_result

def get_aes_key_from_user():
    key_option = input("Choose an option to enter the AES key:\n1. Enter key as a hexadecimal string\n2. Load key from a file\nEnter your choice: ")
    key = None

    if key_option == '1':
        key_input = input("Enter the AES key as a hexadecimal string: ")
        key = bytes.fromhex(key_input)
    elif key_option == '2':
        file_path = input("Enter the file path containing the AES key: ")
        try:
            with open(file_path, 'rb') as file:
                key = file.read()
        except FileNotFoundError:
            print("File not found.")
    else:
        print("Invalid option.")

    return key







#     # Test plaintext
# with open('input.txt', 'rb') as infile:
#     plaintext = infile.read()
# plaintext_data = plaintext 
# private_key, public_key = RSA_generate_key_pair()
# aes_key=get_random_bytes(32)
# # Test the sign_encrypt_plaintext function
# encrypted_data = RSA_sign_and_encrypt(plaintext_data, private_key, aes_key)
# print("Encrypted Data:", encrypted_data)

# # Test the decrypt_verify_data function
# decrypted_text, verification_result = RSA_decrypt_and_verify_data(encrypted_data, public_key, aes_key)

# if verification_result:
#     print("Verification successful.")
#     print("Decrypted Text:", decrypted_text)
# else:
#     print("Verification failed. The data may have been tampered with.")




def get_filenames():
    input_filename = input("Enter the input file name: ")
    output_filename = input("Enter the output file name: ")
    return input_filename, output_filename

def main():
    while True:
        print("\nMain Menu:")
        print("1. AES Operations")
        print("2. RSA Operations")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            aes_key = get_aes_key_from_user()

            while aes_key is None:
                aes_key = get_aes_key_from_user()

            while True:
                print("\nAES Operations Menu:")
                print("1. AES Encryption")
                print("2. AES Decryption")
                print("3. Back to Main Menu")

                aes_choice = input("Enter your choice: ")

                if aes_choice == '1':
                    input_file, output_file = get_filenames()
                    encrypt_file_aes(input_file, output_file, aes_key)
                    print("AES Encryption Successful")
                elif aes_choice == '2':
                    input_file, output_file = get_filenames()
                    decrypt_file_aes(input_file, output_file, aes_key)
                    print("AES Decryption Successful")
                elif aes_choice == '3':
                    break
                else:
                    print("Invalid choice. Please enter a valid option for AES operations.")

        elif choice == '2':
            private_key, public_key = RSA_generate_key_pair()
            RSA_save_key_to_file(private_key, 'private_key.pem')
            RSA_save_key_to_file(public_key, 'public_key.pem')

            while True:
                print("\nRSA Operations Menu:")
                print("1. RSA Encryption")
                print("2. RSA Decryption")
                print("3. RSA Signature")
                print("4. RSA sign and encrypt")
                print("5. RSA decryprt and verify")
                print("6. RSA verify Signature")  
                print("7. Back to Main Menu")

                rsa_choice = input("Enter your choice: ")


                if rsa_choice == '1':
                    input_file, output_file = get_filenames()
                    RSA_encrypt_file(input_file, output_file, public_key)
                    print("RSA Encryption Successful")

                elif rsa_choice == '2':
                    input_file, output_file = get_filenames()
                    RSA_decrypt_file(input_file, output_file, private_key)
                    print("RSA Decryption Successful")

                elif rsa_choice == '3':
                    input_file, output_file = get_filenames()

                    with open(input_file, 'rb') as infile:
                        data = infile.read()  

                    temp = 'temp.tmp'
                    
                    RSA_sign_data(input_file, temp, private_key)

                    with open(temp, 'rb') as signfile:
                            signature = signfile.read()

                # Append the plaintext to the signature
                    signed_data = signature + data

                    with open(output_file, 'wb') as outputfile:
                        outputfile.write(signed_data)

                    print("RSA Signature Created")

                elif rsa_choice == '4':

                    input_file, output_file = get_filenames()
                    aes_key = get_aes_key_from_user()

                    while aes_key is None:
                        aes_key = get_aes_key_from_user()

                    RSA_sign_and_encrypt(input_file, output_file, private_key, aes_key)
                    print("RSA Sign and Encrypt Successful")

                elif rsa_choice == '5':
 
                    input_file, output_file = get_filenames()
                    aes_key = get_aes_key_from_user()

                    while aes_key is None:
                        aes_key = get_aes_key_from_user()

                    verification_result = RSA_decrypt_and_verify_data(input_file, output_file, public_key, aes_key)

                    if verification_result:
                        print("Verification successful.")
                    else:
                        print("Verification failed. The data may have been tampered with.")

                elif rsa_choice == '6':

                    input_file, output_file = get_filenames()

                    with open(input_file, 'rb') as infile:
                        file = infile.read()  
                    # Extract the signature and plaintext
                    signature = file[:256]
                    plaintext = file[256:]

                    data_in = 'data_input_file.tmp'
                    with open(data_in, 'wb') as datafile:
                        datafile.write(plaintext)
                    
                    signature_verification_result = RSA_verify_signature(data_in, signature, public_key)

                    if signature_verification_result:
                        print("Signature is valid.")
                    else:
                        print("Signature is invalid")

                elif rsa_choice == '7':
                    break
                else:
                    print("Invalid choice. Please enter a valid option for RSA operations.")

        elif choice == '3':
            print("Exiting the program...")
            break
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
