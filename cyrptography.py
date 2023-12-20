#   CYPRTOGRAPHY PROJECT
#   BY: Andrea Claire M. Baulita  BSCS - 3

# Program Description: The script demonstrates a basic file encryption and decryption system using
#                      RSA for key management and AES-GCM for symmetric encryption, with HKDF used 
#                      for key derivation. It also includes hash generation for both original and 
#                      encrypted files.

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.kdf.hkdf import HKDF    
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import os
import hashlib

# Function to generate random bytes used in encryption
def get_random_bytes(n):
    return os.urandom(n)


# Function to generate RSA keys both private and public
def generate_keys():
    private_key_path = r'C:\Users\ideaPad Gaming\python files\private_key.pem'

    if os.path.exists(private_key_path):
        # Load existing private key from file
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    else:
        # Generate new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Save the private key to a file
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    public_key = private_key.public_key()
    return public_key, private_key


# Function to derive a key from a password and salt using PBKDF2
def derive_key(password, salt):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'encryption key',
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Function to encrypt a file using RSA and HKDF
def encrypt_file(filename, public_key, password):
    with open(filename, 'rb') as f:
        content = f.read()

        # Generate a random salt for key derivation
        salt = get_random_bytes(16)

        # Derive the symmetric key from the password and salt using HKDF
        symmetric_key = derive_key(password, salt)

        # Generate a random initialization vector (IV) for GCM
        iv = get_random_bytes(16)

        # Create a new AES cipher object with GCM mode
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the content with the AES-GCM cipher
        ciphertext = encryptor.update(content) + encryptor.finalize()

        # Get the GCM tag and concatenate it with the ciphertext
        tag = encryptor.tag
        encrypted_data = salt + iv + tag + ciphertext

        # Encrypt the symmetric key with the RSA public key
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Write the encrypted symmetric key, salt, iv, tag, and the ciphertext to the file
    with open(filename + '.enc', 'wb') as f:
        f.write(encrypted_key)
        f.write(encrypted_data)


# Function to decrypt a file using RSA and HKDF
def decrypt_file(filename, private_key, password):
    try:
        # Read the encrypted file
        with open(filename, 'rb') as f:
            # Read the encrypted key, salt, IV, tag, and ciphertext
            encrypted_key = f.read(private_key.key_size // 8)
            salt = f.read(16)
            iv = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

            # Decrypt the key using the private key
            decrypted_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Derive the symmetric key from the password and salt using HKDF
            symmetric_key = derive_key(password, salt)

            # Create a new AES cipher object with GCM mode
            cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt the content with the AES-GCM cipher
            decrypted_content = decryptor.update(ciphertext) + decryptor.finalize()

        # Derive the decrypted filename from the original filename
        original_filename, original_extension = os.path.splitext(filename.replace('.enc', ''))
        decrypted_filename = original_filename + '_decrypted' + original_extension
        with open(decrypted_filename, 'wb') as f:
            f.write(decrypted_content)

        return decrypted_filename
    
    except Exception as e:
        print("Decryption error: Password incorrect.")
        return None


# Function to generate hash of a file
def generate_hash(filename):
  with open(filename, 'rb') as f:
      content = f.read()
  return hashlib.sha256(content).hexdigest()

# main function
def main():
    # Ask the user for the file name
    filename = input("Enter the name of the file you want to process: ")
    filename = filename.strip('"')

    # Check if the file exists
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        return

    # Check if the file is already encrypted
    if filename.endswith('.enc'):   #! ----- DECRYPTION PROCESS -----
        user_choice = input("The file is already encrypted. Do you want to decrypt it? (y/n): ").lower()
        if user_choice != 'y':
            print("Program ended.")
            return
        else:
            # Ask the user for the password
            password = input("Enter the password: ")

            # Generate RSA keys
            public_key, private_key = generate_keys()

            # Generate the hash of the encrypted file
            encrypted_hash = generate_hash(filename)
            print(f"Encrypted File Hash: {encrypted_hash}")

            # Generate the hash of the decrypted file
            decrypted_filename = decrypt_file(filename, private_key, password)
            if decrypted_filename is not None:
                print("Decryption successful!")
                decrypted_hash = generate_hash(decrypted_filename)
                print(f"Decrypted File Hash: {decrypted_hash}")
    else: #! ----- ENCRYPTION PROCESS -----
        user_choice = input("Do you want to encrypt the file? (y/n): ").lower()
        if user_choice != 'y':
            print("Program ended.")
            return
        else:
            # Ask the user for the password
            password = input("Enter the password: ")

            # Generate RSA keys
            public_key, _ = generate_keys()

            # Generate the hash of the original file
            original_hash = generate_hash(filename)
            print(f"Original File Hash: {original_hash}")

            # Encrypt the file using RSA and HKDF
            encrypt_file(filename, public_key, password)
            print("Encryption successful!")

            # Generate the hash of the encrypted file
            encrypted_filename = filename + '.enc'
            encrypted_hash = generate_hash(encrypted_filename)
            print(f"Encrypted File Hash: {encrypted_hash}")

if __name__ == "__main__":
    main()



