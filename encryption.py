#Importing the required modules for RSA encrption and decryption.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64
# function to generate public and private key
def generate_key_pair():
    #2048 bit key
    key = RSA.generate(2028) 
    #exports private key in pem format
    private_key = key.export_key() 
    #exporting public key in pem format
    public_key = key.publickey().export_key() 
    #returning private and public key.
    return private_key, public_key 

#Function to save keys
def save_key_to_file(key, filename): 
    #opens file in write binary mode
    with open(filename, 'wb') as key_file: 
        #writes the key.
        key_file.write(key) 

#Function to load the generated key
def load_key_from_file(filename): 
    #opens the file in read binary mode
    with open(filename, 'rb') as key_file: 
        #read the key and saves in key object.
        key = RSA.import_key(key_file.read()) 
        return key

#Encrypt file user-defined function
def encrypt_file(file_path, public_key_path, output_file_path):
    # Load the public key
    public_key = load_key_from_file(public_key_path)

    # Create a cipher using the public key
    cipher = PKCS1_OAEP.new(public_key)

    # Read the plaintext file
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)
    base64_ciphertext = base64.b64encode(ciphertext)
   # print(base64_ciphertext)
    # Write the encrypted data to the output file
    with open(output_file_path, 'wb') as encrypted_file:
        #write the ciphertext in output file
        encrypted_file.write(base64_ciphertext)



#Digital Signature. 
#Generating key for Digitla signature
def generate_keys_digital_signature():
    # Generate a new RSA key pair with 2048 bits
    key = RSA.generate(2048)
    # Export the private and public keys
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
#Saving the keys.
def save_keys_to_file(key, filename): 
    #opens file in write binary mode
    with open(filename, 'wb') as key_file: 
        #writes the key.
        key_file.write(key) 

#Signature function
def sign_file_message(private_key, file_path,signature_path):
    # Import the private key
    key = RSA.import_key(private_key)
    with open(file_path, 'rb') as encrypted_file: 
        #reads cipher text 
        message = encrypted_file.read() 

    # Create a SHA-256 hash object from the message
    h = SHA256.new(message)     #Hash function
    # Sign the hash using PKCS#1.5 padding scheme
    signature = pkcs1_15.new(key).sign(h)
    # Save the signature to a file
    with open(signature_path, 'wb') as signature_file:
        signature_file.write(signature)
    return signature




#Main function
if __name__ == "__main__":
    #Input file to encrypt
    input_file = "file.txt"

#Exception handing try block and encryption for user-1.
try:
    #File path for user-1's public key
    public_key_file_user1_path = "user_1\Encryption\public_key.pem"
    private_key_file_user1_path = "user_1\Encryption\private_key.pem"
    # File path for user-1's encrypted file
    encrypted_file_user1_path = "user_1\Encryption\encrypted_file.bin"
    
    # Generate a key pair for user-1
    private_key_user1, public_key_user1 = generate_key_pair()
    
    # Save user-1's private and public keys to files
    save_key_to_file(private_key_user1, private_key_file_user1_path)
    save_key_to_file(public_key_user1, public_key_file_user1_path)
    
    # Encrypt a file.txt input file using user-1's public key
    encrypt_file(input_file, public_key_file_user1_path, encrypted_file_user1_path)
     # Print a success message if the encryption for user-1 is successfull
    print(f"File successfully encrypted for user-1")
except Exception as e:
    # Print an error message if an exception occurs during the encryption process for user-1
    print(f"An error occurred while encrypting file for user-1: {e}")

try:
#Digital Signature Part.->user_1
    # Signing the encrypted file with digital signature
    private_key_signature_user1, public_key_signature_user1 = generate_keys_digital_signature()
    public_key_signature_user1_file_path = "user_1\Digital_Signature\public_key.pem"
    private_key_signature_user1_file_path = "user_1\Digital_Signature\private_key.pem"
    #Saving keys.
    save_keys_to_file(private_key_signature_user1, private_key_signature_user1_file_path)
    save_keys_to_file(public_key_signature_user1, public_key_signature_user1_file_path)
    # File path for user-1's encrypted file
    signature_file_user1_path = "user_1\Digital_Signature\signature.sig"
    # Sign the message
    signature = sign_file_message(private_key_signature_user1, encrypted_file_user1_path,signature_file_user1_path)
    print(f"Encrypted File successfully digitally signed for user-1")

except Exception as e:
    # Print an error message if an exception occurs during the signing process for user-1
    print(f"An error occurred while signing file for user-1: {e}")



 


# Encryption for user-2
try:
    #File path for user-2's public key
    public_key_file_user2_path = "user_2\Encryption\public_key.pem"
    private_key_file_user2_path = "user_2\Encryption\private_key.pem"
    # File path for user-2 encrypted file
    encrypted_file_user2_path = "user_2\Encryption\encrypted_file.bin"
    
    # Generate a key pair for user-2
    private_key_user2, public_key_user2 = generate_key_pair()
    
    # Save user-2's private and public keys to files
    save_key_to_file(private_key_user2, private_key_file_user2_path)
    save_key_to_file(public_key_user2, public_key_file_user2_path)
    
    # Encrypt a input file file.txt using user-2's public key
    encrypt_file(input_file, public_key_file_user2_path, encrypted_file_user2_path)
    
    # Print a success message if the encryption for user-2 is successfull
    print(f"File successfully encrypted for user-2")
except Exception as e:
    # Print an error message if an exception occurs during the encryption process for user-2
    print(f"An error occurred while encrypting file for user-2: {e}")

try:
#Digital Signature Part.->user_2
    # Signing the encrypted file with digital signature
    private_key_signature_user2, public_key_signature_user2 = generate_keys_digital_signature()
    public_key_signature_user2_file_path = "user_2\Digital_Signature\public_key.pem"
    private_key_signature_user2_file_path ="user_2\Digital_Signature\private_key.pem"
    #Saving keys.
    save_keys_to_file(private_key_signature_user2, private_key_signature_user2_file_path)
    save_keys_to_file(public_key_signature_user2, public_key_signature_user2_file_path)
    # File path for user-1's encrypted file
    signature_file_user2_path = "user_2\Digital_Signature\signature.sig"
    # Sign the message
    signature = sign_file_message(private_key_signature_user2, encrypted_file_user2_path,signature_file_user2_path)
    print(f"Encrypted File successfully digitally signed for user-2")

except Exception as e:
    # Print an error message if an exception occurs during the signing process for user-2
    print(f"An error occurred while signing file for user-2: {e}")
