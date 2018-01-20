# simple-file-crypt
Simple file encryption and decryption module for python 2.7 and provides confidentiality, integrity and authenticity

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
      
