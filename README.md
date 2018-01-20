# simple-file-crypt
Simple file encryption and decryption module for python 2.7 and provides confidentiality, integrity and authenticity

# Protocol
simple-file-crypt uses sign-encrypt-sign method to secure file ecnryption and decryption.
      1) It signs the hash(M) and generates 256-bit key(Ks) for AES-GCM encryption.
      2) It encrypts [M || hash(M)] using AES-GCM mode. I also authenticate the hash(M) using authentication mode in GCM.
      3) Next, it encrypts symmetric key (Ks) with public key of receiver and sign the encrypted symmetric key with sender’s private key.
      4) Lastly it checks the hash of decrypted file thus verifying successful decryption.

# Algorithm
Symmetric encryption algorithm: AES-GCM-256 which uses 256-bit key. Why AES-GCM mode? Because:
      1) It is authenticated encryption algorithm which provides data integrity and confidentiality
 	2) it is efficient and shows better performance. 
      3) Additional authenticated data is used to authenticate the data and only after that AES-GCM decrypts data

Asymmetric encryption and signing algorithm: OAEP RSA algorithm (I used key size of 2048 bits but the program is compatible with 4096 or 1024 bits as well). Why RSA 2048? Because:
      1)	RSA encrypts and signs data using OAEP which is different from textbook RSA.
      2)	Key size of 2048 is considered to be secure and unbroken

Hash Algorithm: SHA256 algorithm is relatively secure

# Usage: Encryption
      python fcrypt.py destination_public_key.der sender_private_key.pem input_plaintext encrypted_text

# Usage: Decryption
      python fcrypt.py destination_private_key.pem sender_public_key.der encrypted_text decrypted_text
      
# Steps to generate public-private key pair
      ## generate public-private key pair for sender
      openssl genrsa -out sender_private_key.pem 2048
      openssl genrsa -in sender_private_key.pem -outform DER -pubout -out sender_public_key.der
      
      ## generate public-private key pair for receiver
      openssl genrsa -out destination_private_key.pem 2048
      openssl genrsa -in destionation_private_key.pem -outform DER -pubout -out destionation_public_key.der
      
