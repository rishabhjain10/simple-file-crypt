import os
import os.path
import sys
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
import pickle

# This loop check for valid arguments and whether key file and input file exist or not
if len(sys.argv)==6:
    if sys.argv[1] == ("-e") and os.path.exists(sys.argv[2]) and os.path.exists(sys.argv[3]) and os.path.exists(sys.argv[4]) and sys.argv[5] !=None:
            dest_public_key = sys.argv[2]
            send_private_key = sys.argv[3]
            input_plaintext_file = sys.argv[4]
            output_ciphertext_file = sys.argv[5]
    elif sys.argv[1] == ("-d") and os.path.exists(sys.argv[2]) and os.path.exists(sys.argv[3]) and os.path.exists(sys.argv[4]) and sys.argv[5] !=None:
            dest_private_key = sys.argv[2]
            send_public_key = sys.argv[3]
            input_ciphertext_file = sys.argv[4]
            output_plaintext_file = sys.argv[5]        
    else:
            print 'Command: options -e [dest_pub_key] [sender_pri_key] [input file] [outputfile]'
            print 'Command: options -d [dest_pri_key] [sender_pub_key] [input file] [outputfile] in '
            sys.exit()
else:
    print 'Command: options -e [dest_pub_key] [sender_pri_key] [input file] [outputfile]'
    print 'Command: options -d [dest_pri_key] [sender_pub_key] [input file] [outputfile]'
    sys.exit()

# Signing with private key of sender so that receiver can verify the signature 
def sign_message(message):
    signer = sender_private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    signer.update(message)
    signature = signer.finalize()
    return signature

# Verifying with public key of sender so that receiver is assured that only sender could have sent the data
def verify(signature,message):
    ver =sender_public_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
    ver.update(message)
    return ver.verify()

# This code decrypts ciphertext using AES-GCM mode with symmetric key
def decrypt(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

# This decrypts data using RSA private key of recevier
def asymmetric_decryption(message):
    plaintext = receiver_private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None))
    return plaintext

# This encrypts data using RSA public key of receiver so that only receiver who owns private key can decrypt it
def asymmetric_encryption(message):
    ciphertext = receiver_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None))
    return ciphertext

# This encrypts plain text and signature of hash message and authenticates the hash of message 
def encrypt(key, plaintext, additional_authenticated_data):
    # IV length = 12 * 8 = 96 bits
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor() # AES_GCM mode with 256 bit symmetric key
    encryptor.authenticate_additional_data(additional_authenticated_data) # Authenticaed data in our case its hash(plain_message)
    # sign hash of message with private key
    signature = sign_message(additional_authenticated_data) # additional_authenticated_data == hash_of_message
    m1 = (plaintext,signature)
    m = pickle.dumps(m1) # serializes data
    ciphertext = encryptor.update(m) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

# This produces SHA256 message digest
def hashm(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash_of_message = digest.finalize()
    return hash_of_message

def error(message):
    print "Error in " + message
    sys.exit()


# This code works if "-e" is used, to encrypt and sign the message
if sys.argv[1] == "-e":
    
    # loads public key der file
    with open(dest_public_key, "rb") as key_file:
     receiver_public_key = serialization.load_der_public_key(
            key_file.read(),
            backend=default_backend())

    # loads private key pem file
    with open(send_private_key, "rb") as key_file:
     sender_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    sender_public_key = sender_private_key.public_key()


    # Generates 256-bit symmetric key used for AES-GCM mode encryption and authentication of data
    key = os.urandom(32)
    
    #opens input text file and reads the data from it
    try:
        input_file = open(input_plaintext_file,"r+")
        plaintext = input_file.read()
    except:
        error("Couldn't open file")

    # Generated hash for message, algorithm used is SHA-256
    try:
        additional_authentication_data = hashm(plaintext)
        hash_of_message = additional_authentication_data
    except:
        error("Generating hash function")

    # Encrypts the plaintext and authenticates hash of message using AES-GCM mode
    try:
        iv, ciphertext, tag = encrypt(key,plaintext,additional_authentication_data)
    except:
        error("Symmetric Encryption failed")

    # encrypts the symmetric key
    try:
        encrypted_asymmetric_key = asymmetric_encryption(key)
    except:
        error("Assymmetric Encryption failed")

    # signs the encrypted symmetric key
    try:
        encrypted_and_signed_key = sign_message(encrypted_asymmetric_key)
    except:
        error("Signing message")

    try:
        message_sent_to_destination = (encrypted_and_signed_key, encrypted_asymmetric_key, iv, hash_of_message, tag, base64.b64encode(ciphertext))
        serialized_data = pickle.dump(message_sent_to_destination,open(output_ciphertext_file,"w+"))
    except:
        error("Serialization failed in pickle")


# This executes only when "-d" is selected meaning decryption and verification at receiver side    
elif sys.argv[1] == "-d":

    with open(dest_private_key, "rb") as key_file:
     receiver_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    receiver_public_key = receiver_private_key.public_key()

    with open(send_public_key, "rb") as key_file:
     sender_public_key = serialization.load_der_public_key(
            key_file.read(),
            backend=default_backend())
    ""
    # Reads and deserializes the data
    unmessage = pickle.load(open(input_ciphertext_file,"r+"))
    encrypted_and_signed_key, encrypted_asymmetric_key, iv, hash_of_message, tag, encoded_ciphertext = unmessage
    ciphertext = base64.b64decode(encoded_ciphertext)
    
    try:
        verify(encrypted_and_signed_key,encrypted_asymmetric_key)
    except:
        error("Verificatio failed")

    try:
        symmetric_key = asymmetric_decryption(encrypted_asymmetric_key)
    except:
        error("Asymmetric decryption failed")

    try:
        plaintext = decrypt(symmetric_key,hash_of_message,iv,ciphertext,tag)
        plaindata, signature = pickle.loads(plaintext)
    except:
        error("Symmetric decryption failed")

    try:
        calculated_hash_of_plaintext = hashm(plaindata)
        verify(signature,calculated_hash_of_plaintext)
    except:
        error("Signature verification failed")
    
    try:
        o = open(output_plaintext_file,"w+")
        o.write(plaindata)
    except:
        error("Opening "+output_plaintext_file)

else:
    error("some thing went wrong")
