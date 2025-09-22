# AdvanceEncryptionTool

*COMPANY* : CODTECH IT SOLUTIONS PVT.LTD

*NAME* : MOHAMMED MARDAN ALI

*INTERN ID* : CT04DY1075

*DOMAIN* : CYBER SECURITY AND ETHICAL HACKING 

*DURATION* : 4 WEEKS

*MENTOR* : NEELA SANTOSH KUMAR

## Project Description

This project is a desktop application that provides a robust and user-friendly interface for encrypting and decrypting files using the powerful Advanced Encryption Standard (AES-256) in Galois/Counter Mode (GCM).
The application is built with Python and the tkinter library for the graphical interface, making it accessible to users with minimal technical knowledge.

## Project architecture
The application is designed to be straightforward and secure, with a separation of concerns:

-Cryptographic core: The secure encryption and decryption logic is contained within the functions encrypt_aes_gcm and decrypt_aes_gcm. This logic handles the complex parts of the process, including key derivation, encryption, and data integrity verification.

-User interface layer: The EncryptionApp class uses the tkinter library to create and manage all elements of the GUI. It handles user input (file selection and password entry) and button clicks, and then calls the appropriate functions from the cryptographic core.

## Core technologies

-Python: The programming language used to build the entire application.

-tkinter: Python's standard GUI library, used to create the graphical interface.

-pycryptodome: A Python package that provides robust implementations of cryptographic algorithms, including AES and Scrypt.


## Key algorithms

-AES-256 GCM: The core symmetric encryption algorithm. AES-256 uses a 256-bit key for a very high level of security. GCM is an "authenticated encryption" mode that verifies the file's integrity, ensuring the encrypted data hasn't been tampered with.
 
-Scrypt: A secure key derivation function (KDF) that creates a strong, machine-readable encryption key from a human-readable password. Scrypt is computationally expensive, which makes it highly resistant to brute-force password-guessing attacks.

## Functionality walkthrough

-GUI Initialization: When the user runs the advance_encryption_tool.py script, a graphical window appears with a title, "Advance Encryption Tool".

-File Selection: The user can click the "Browse" button to open a file dialog, allowing them to select any file they wish to encrypt or decrypt.

-Password Entry: The user enters a password into a text box. The input is masked with asterisks (*) for security.
    
## Encryption:
      
1. The user clicks the "Encrypt" button.

2. The application prompts the user to select a location and filename for the encrypted output file (with a default .enc extension).

3. The tool securely derives a unique key from the user's password using Scrypt and a random salt.

4. The file is encrypted using the derived key and the AES-256 GCM algorithm.

5.The encrypted data, along with the salt and other metadata, is saved to the specified output file.
  
## Decryption:
    
1. The user clicks the "Decrypt" button after selecting an encrypted .enc file.

2. The application prompts the user to choose a destination and name for the decrypted output file.

3. The tool reads the encrypted data and metadata from the file.

4. The tool uses the same Scrypt algorithm and the stored salt to regenerate the encryption key from the user-provided password.

5. The data is decrypted and its integrity verified.

6. The original file content is written to the new, user-specified output file. 


## Security features

1. Strong Algorithm: The use of AES-256 is the foundation of the tool's security, as it is a standard trusted by many governments and corporations for securing sensitive data.

2. Authenticated Encryption: GCM mode ensures that a file cannot be decrypted if it has been tampered with since it was encrypted, adding a layer of integrity checking.

3. Secure Password Handling: Scrypt makes the process of converting a password to a key highly resistant to offline brute-force attacks, as it is slow and memory-intensive to compute.

4. Zero-Knowledge: The application does not store the user's password or key, and the key is never transmitted or stored outside of the encrypted file's metadata.

## Output

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/462c222d-cfbd-4301-ba78-9287817b92d6" />

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/a5551d04-be25-477c-84aa-2350be4fd2c6" />

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/47be244d-0ebc-4dcb-bfc2-a7648ef356c0" />

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/820b930f-b031-489c-9e7a-9e8506944866" />

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/fbec1f40-d764-4fb4-b114-4a19c6d80261" />

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/121a94a3-2e43-46d9-9816-2ab949375a9f" />

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/a05b73de-a8bd-44b0-8b5e-3ff3b0be9af6" />
