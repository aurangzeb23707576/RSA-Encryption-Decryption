#Importing the required modules for RSA encrption and decryption.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64
#Load key function for load private key 
def load_key_from_file(filename): 
    #Opens file in read binary mode.
    with open(filename, 'rb') as key_file: 
        #reads the key content from file and saves in key object.
        key = RSA.import_key(key_file.read()) 
        return key #Returns the key.

#Decrypt key function
def decrypt_file(file_path, private_key_path, output_file_path):
    # Load the private key
    private_key = load_key_from_file(private_key_path)

    # Create a cipher object using the private key
    cipher = PKCS1_OAEP.new(private_key)

    # Reading the encrypted file in read binary mode
    with open(file_path, 'rb') as encrypted_file: 
        #reads cipher text 
        ciphertext = encrypted_file.read() 
    base64ciphertext = base64.b64decode(ciphertext)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(base64ciphertext)

    # Write the decrypted data to the output file in write binary mode
    with open(output_file_path, 'wb') as decrypted_file: 
        #writes decrypted content in output file
        decrypted_file.write(plaintext) 


def verify_signature(public_key_path, encrypted_file_path, signature_path):
    # Import the public key
    with open(public_key_path, 'rb') as public_key_file:
        public_key = RSA.import_key(public_key_file.read())


    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_file_content = encrypted_file.read()

    # Create a SHA-256 hash object from the message
    h = SHA256.new(encrypted_file_content)

    with open(signature_path, 'rb') as signature_file:
        signature = signature_file.read()
    try:
        # Verify the signature using PKCS#1.5 padding and public key
        pkcs1_15.new(public_key).verify(h, signature)
        return True  # Signature is valid and encrypted file is not tampered or modified
    except (ValueError, TypeError):
        return False  # Signature is not valid and encrypted file is tampered/ modified


#Defining decryption function for user1
def decryption_user_1():
           #user -1
    #Exception handing incase of error.
    try:
        #Private key path for user-1
        private_key_file_user1_path = "user_1\Encryption\private_key.pem"

        #File path of encrypted file of user-1
        encrypted_file_user1_path = "user_1\Encryption\encrypted_file.bin"

        #Output path of decrypted file for user-2
        decrypted_file_user1_path = "user_1\Decryption\decrypted_file.txt"

        #Executes decrypt file function, and passed encrypted file,
        # private key and output path of file as parameters
        decrypt_file(encrypted_file_user1_path, private_key_file_user1_path, decrypted_file_user1_path)

        #Succesfully prints message if file is successfully decrypted for user-1
        print(f"File are successfully decrypted for the user-1")

    except Exception as e:
          #prints message if error occurs while decrypting file for user-1
        print(f"An error occurred for while decrypting file for user-1: {e}")

    try:
    
        #Public key path of signature for user-1
        public_key_digital_sign_user1_path = "user_1\Digital_Signature\public_key.pem"
        #Signature path for user-1 encrypted file
        signature_file_user1_path = "user_1\Digital_Signature\signature.sig"
        #File path of encrypted file of user-1

        encrypted_file_user1_path = "user_1\Encryption\encrypted_file.bin"
        is_valid= verify_signature(public_key_digital_sign_user1_path,encrypted_file_user1_path,signature_file_user1_path)
        print("Is the signature valid?", is_valid)
        exit

    except Exception as e:
          #prints message if error occurs while verifying signature file for user-1
        print(f"An error occurred for while verifying the signature file for user-1: {e}")


#Defining function for user2
def decryption_user_2():
     #user-2
    try:
        #Private key path for user-2
        private_key_file_user2_path = "user_2\Encryption\private_key.pem"

        #File path of encrypted file of user-2
        encrypted_file_user2_path = "user_2\Encryption\encrypted_file.bin"

        #Output path of decrypted file for user-2
        decrypted_file_user2_path = "user_2\Decryption\decrypted_file.txt"

        #Executes decrypt file function, and passed encrypted file,
        # private key and output path of file as parameters
        decrypt_file(encrypted_file_user2_path, private_key_file_user2_path, decrypted_file_user2_path)

        #Prints message if file is successfully decrypted for user-2.
        print(f"File are successfully decrypted for the user-2")


    except Exception as e:
        #prints message if error occurs while decrypting file for user-2
        print(f"An error occurred for while decrypting file for user-2: {e}")


    try:
        
        #Public key path of signature for user-2
        public_key_digital_sign_user2_path = "user_2\Digital_Signature\public_key.pem"
        #Signature path for user-1 encrypted file
        signature_file_user2_path = "user_2\Digital_Signature\signature.sig"
       
        is_valid= verify_signature(public_key_digital_sign_user2_path,encrypted_file_user2_path,signature_file_user2_path)
        print("Is the signature valid?", is_valid)
        exit


    except Exception as e:
          #prints message if error occurs while verifying signature file for user-2
        print(f"An error occurred for while verifying the signature file for user-2: {e}")

if __name__ == "__main__":
    #Exception handling
    try:
        #Ask the user to enter his choice 1 or 2?
        user_choice = int(input("Enter 1  if you want decrypt files for User-1, 2 if you want decrypt files for User-2: "))
        #Defined a dictionery for user choice for each function
        user_actions = {
            1: decryption_user_1,
            2: decryption_user_2
        }
        #Check if user choice is correct
        if user_choice in user_actions:
            #Executing the function based on user input
            user_actions[user_choice]()
        else:
            #shows error message if user enters wrong choice and exits the program.
            print("Invalid choice. Please enter 1 or 2.")
            exit
    except ValueError:
        #shows error message if user enters non numeric value.
        print("Invalid input. Please enter a number.")
    except Exception as e:
         #shows error message if any other error occurs during runtime.
        print(f"An error occurred: {e}")