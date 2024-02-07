# Write your script here
import secrets,random,hmac,os,pyaes,hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding,ec
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.exceptions import InvalidSignature,InvalidTag
from base64 import b64encode, b64decode

def pad(data, block_size):
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def rsa_key_pair(exponent=65537,key_size=2048,backend = default_backend()):
    private_key = rsa.generate_private_key(
            public_exponent=exponent,
            key_size=key_size,
            backend=backend
        )
    public_key = private_key.public_key()
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()),public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

def ecc_key_pair(curve = ec.SECP256R1(),backend=default_backend()):
    private_key = ec.generate_private_key(
        curve= curve,
        backend=backend
        )
    public_key = private_key.public_key()
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()),public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here
        symmetric_key = random.getrandbits(128).to_bytes(16, byteorder='big')
        private_key_sender_rsa,public_key_sender_rsa = rsa_key_pair()
        private_key_receiver_rsa,public_key_receiver_rsa = rsa_key_pair()
        private_key_sender_ecc,public_key_sender_ecc = ecc_key_pair()


        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here
        nonce_aes_cbc = secrets.token_bytes(16)
        nonce_aes_ctr = secrets.token_bytes(16)
        nonce_encrypt_rsa = secrets.token_bytes(32)
        nonce_aes_cmac = secrets.token_bytes(16)
        nonce_hmac = secrets.token_bytes(16)
        nonce_tag_rsa = secrets.token_bytes(32)
        nonce_ecdsa = secrets.token_bytes(32)
        nonce_aes_gcm = secrets.token_bytes(12)


        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""
        key_,plaintext_,nonce_ = key,plaintext,nonce
        # Write your script here
        backend = default_backend()
        ciphertext = None

        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            key_ = key_[:16]
            block_size = 16
            plaintext_ = pad(plaintext_, block_size)
            print(len(plaintext_))
            iv = os.urandom(16)
            aes = pyaes.AESModeOfOperationCBC(key_, iv=nonce)
            ciphertext = aes.encrypt(plaintext_)

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            key_ = key_[:16] 
            aes = pyaes.AESModeOfOperationCTR(key_, counter=pyaes.Counter(initial_value=int.from_bytes(nonce_, byteorder='big')))
            ciphertext = aes.encrypt(plaintext_)

        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            public_key = serialization.load_pem_public_key(key_, backend=backend)
            ciphertext = public_key.encrypt(
                plaintext_,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            ciphertext = b64encode(ciphertext)

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this
        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here
        key_,ciphertext_,nonce_ = key,ciphertext,nonce
        backend = default_backend()
        plaintext = None
        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here
            key_ = key_[:16]
            aes = pyaes.AESModeOfOperationCBC(key_, iv=nonce_ )
            padded_plaintext = aes.decrypt(ciphertext_)
            plaintext = unpad(padded_plaintext)

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            key_ = key_[:16]
            aes = pyaes.AESModeOfOperationCTR(key_, counter=pyaes.Counter(initial_value=int.from_bytes(nonce_, byteorder='big')))
            plaintext = aes.encrypt(ciphertext_)

        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            private_key = serialization.load_pem_private_key(
                key_, password=None, backend=backend
            )
            ciphertext_ = b64decode(ciphertext_)
            plaintext = private_key.decrypt(
                ciphertext_,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here
        key_,plaintext_ = key,plaintext
        backend = default_backend()
        auth_tag = None

        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            key_ = key_[:16]
            cipher = CMAC(algorithms.AES(key_), backend=backend)
            cipher.update(plaintext_)
            auth_tag = cipher.finalize()

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            h = hmac.new(key_, digestmod=hashlib.sha3_256)
            h.update(plaintext_)
            auth_tag = h.digest()

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            private_key = serialization.load_pem_private_key(key_, password=None, backend=backend)
            signature = private_key.sign(
                plaintext_,
                padding.PKCS1v15(),
                hashes.SHA3_256()
            )
            auth_tag = b64encode(signature)

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            private_key = serialization.load_pem_private_key(key_, password=None, backend=backend) 
            signature = private_key.sign(
                plaintext_,
                padding.PKCS1v15(),
                hashes.SHA3_256()
            )
            auth_tag = b64encode(signature)

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here
        key_,plaintext_,auth_tag_ = key,plaintext,auth_tag
        backend = default_backend()
        auth_tag_valid = None

        if algo =='AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            key_ = key_[:16]
            cipher = CMAC(algorithms.AES(key_), backend=backend)
            cipher.update(plaintext_)
            try:
                cipher.verify(auth_tag_)
                auth_tag_valid = True
            except InvalidSignature:
                auth_tag_valid = False


        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            h = hmac.new(key_, digestmod=hashlib.sha3_256)
            h.update(plaintext_)
            calculated_auth_tag = h.digest()
            auth_tag_valid = hmac.compare_digest(calculated_auth_tag, auth_tag)

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            public_key = serialization.load_pem_public_key(key_, backend=backend)
            try:
                signature = b64decode(auth_tag)
                public_key.verify(
                    signature,
                    plaintext_,
                    padding.PKCS1v15(),
                    hashes.SHA3_256()
                )
                auth_tag_valid = True
            except InvalidSignature:
                auth_tag_valid = False

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            public_key = serialization.load_pem_public_key(key_, backend=backend)
            try:
                signature = b64decode(auth_tag)
                public_key.verify(
                    signature,
                    plaintext_,
                    padding.PKCS1v15(),
                    hashes.SHA3_256()
                )
                auth_tag_valid = True
            except InvalidSignature:
                auth_tag_valid = False


        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here
        key_encrypt_, key_generate_auth_, plaintext_, nonce_ = key_encrypt, key_generate_auth, plaintext, nonce
        ciphertext = None
        auth_tag = None
        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            ciphertext = self.encrypt('AES-128-CTR-ENC',key_encrypt_,plaintext_,nonce_)
            auth_tag = self.generate_auth_tag('AES-128-CMAC-GEN',key_generate_auth_,plaintext_,nonce_)
            
        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here
        key_decrypt_, key_verify_auth_, ciphertext_, nonce_, auth_tag_ = key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag
        plaintext = None
        auth_tag_valid = None

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            plaintext = self.decrypt('AES-128-CTR-DEC',key_decrypt_,ciphertext_,nonce_)
            auth_tag_valid = self.verify_auth_tag('AES-128-CMAC-VRF',key_verify_auth_,plaintext,nonce_,auth_tag)
        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this