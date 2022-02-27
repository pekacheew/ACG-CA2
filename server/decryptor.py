import pickle, os, hashlib
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5, AES  
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from pathlib import Path
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

BASE_DIR = Path(__file__).parent.parent
DECRYPTED_DATA_DIR = BASE_DIR / 'server' / 'decryptedData'
ENCRYPTED_DATA_DIR = BASE_DIR / 'server' / 'data'
PRIVATE_KEY_LOC = BASE_DIR / 'server' / 'private.pem'

class ENC_payload:
    # A data class to store a encrypted file content.
    # The file content has been encrypted using an AES key.
    # The AES key is encrypted by a public key and stored in the enc_session_key instance attribute. 
    def __init__(self):
        self.enc_session_key=""
        self.aes_iv = ""
        self.encrypted_content=""
        self.signature = ""
        self.pub_key = ""

# current_dir = os.getcwd()
#print(current_dir)
os.chdir(ENCRYPTED_DATA_DIR)
# os.chdir('D:\SP School\Y1 SEM2\ACG\Assignment 2\assignment_base\source\server\data')



for every_file in os.listdir():  # checks directory file by file
    hash = hashlib.new('SHA256')
    #print(every_file)
    pri_key_content=open(PRIVATE_KEY_LOC,"r").read()
    
    pri_key=RSA.import_key(pri_key_content)
    keysize=pri_key.size_in_bytes()
    data=open(every_file,"rb").read()
    rsa_cipher = PKCS1_OAEP.new(pri_key)
    if len(data) > keysize:   # encrypted file will be in the mulitples of the keysize.
        # need to decrypt the data in with AES
        enc_payload = pickle.loads(data)
        if type(enc_payload) != ENC_payload:
            raise RuntimeError("Invalid encrypted file")
        aes_key=rsa_cipher.decrypt(enc_payload.enc_session_key) # retreive and decrypt the AES key
        aes_cipher = AES.new(aes_key,AES.MODE_CBC,iv=enc_payload.aes_iv)
        signature = enc_payload.signature
        enc_pub_key = enc_payload.pub_key

        pub_key = RSA.import_key(enc_pub_key)
        # print(file_hash)
        plain_text = unpad(aes_cipher.decrypt(enc_payload.encrypted_content), AES.block_size)
        # print(newFile_hash)
        hash2 = SHA256.new(plain_text)

        try:
            pkcs1_15.new(pub_key).verify(hash2, signature)
            print(f"The signature is valid for {every_file}. Data is unaltered.")
        except(ValueError, TypeError):
            print(f"This is not the original data for {every_file}.")

    else:    
       
        plain_text = rsa_cipher.decrypt(data)
    out_bytes=open(every_file,"wb").write(plain_text)

    os.rename(os.path.join(ENCRYPTED_DATA_DIR, every_file), os.path.join(DECRYPTED_DATA_DIR, every_file)) # one of the last lines in this
    