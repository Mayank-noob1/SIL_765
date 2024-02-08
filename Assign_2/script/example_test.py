from execute_crypto import ExecuteCrypto
import time

msg = "Paris 2024 will see a new vision of Olympism in action, delivered in a unique spirit of international celebration."
# Computational ,Communication and storage costs !
t = time.time()

ec = ExecuteCrypto()
print("Object creation time:",time.time()-t)
t = time.time()

# Generating keys
keys = ec.generate_keys()
print("Key generation time:",time.time()-t)
t = time.time()

# Generating nonces
nonces = ec.generate_nonces()
print("Nonces generation time:",time.time()-t)


# Encryption - Decryption Unit Test

def log1(algo,plain,cipher,key,nonce,start,end):
    print(algo +" time:", end-start,end='')
    print('s')
    print("Length of plaintext:",len(plain))
    print("Length of ciphertext:",len(cipher))
    print("Length of key:",len(key))
    print("Length of nonce",len(nonce))

'''
AES-128-CBC-ENC:
    128 bit symmetric key
'''
algo = 'AES-128-CBC-ENC'
key = keys[0]
nonce = nonces[0]
start = time.time()

AesCbcCipher = ec.encrypt(algo,key,msg,nonce)
log1(algo,msg,AesCbcCipher,key,nonce,start,time.time())

'''
AES-128-CBC-DEC:
    128 bit symmetric key
'''
algo = 'AES-128-CBC-DEC'
start = time.time()
AesCbcPlain = ec.decrypt(algo,key,AesCbcCipher,nonce)
log1(algo,AesCbcPlain,AesCbcCipher,key,nonce,start,time.time())

'''
AES-128-CTR-ENC:
    128 bit symmetric key
'''
algo = "AES-128-CTR-ENC"
nonce = nonces[1]
start= time.time()
AesCtrCipher =ec.encrypt(algo,key,msg,nonce)
log1(algo,msg,AesCtrCipher,key,nonce,start,time.time())

'''
AES-128-CTR-DEC:
    128 bit symmetric key
'''
algo = "AES-128-CTR-DEC"
start = time.time()
AesCtrPlain = ec.decrypt(algo,key,AesCtrCipher,nonce)
log1(algo,AesCtrPlain,AesCtrCipher,key,nonce,start,time.time())

'''
RSA-2048-ENC:
    2048 bit public , private key pair
'''
algo ="RSA-2048-ENC"
key = keys[3]
nonce = nonces[2]
start = time.time()
RsaCipher = ec.encrypt(algo,key,msg.encode(),nonce)
log1(algo,msg,RsaCipher,key,nonce,start,time.time())


'''
RSA-2048-DEC:
    2048 bit public , private key pair
'''
algo = "RSA-2048-DEC"
key = keys[4]
start = time.time()
RsaPlain = ec.decrypt(algo,key,RsaCipher,nonce)
log1(algo,RsaPlain,RsaCipher,key,nonce,start,time.time())

# Authentication - Verification Unit Test
def log2(algo,key,plain,auth_tag,nonce,start,end):
    print(algo +" time:", end-start,end='')
    print('s')
    print("Length of plaintext:",len(plain))
    print("Length of auth_tag:",len(auth_tag))
    print("Length of key:",len(key))
    print("Length of nonce",len(nonce))


'''
AES-128-CMAC-GEN:
    128 bit symmetric key
'''
algo = "AES-128-CMAC-GEN"
key = keys[0]
nonce = nonces[3]
start = time.time()
AesCmacAuthTag =ec.generate_auth_tag(algo,key,msg,nonce)
log2(algo,key,msg,AesCmacAuthTag,nonce,start,time.time())

'''
AES-128-CMAC-VRF:
    128 bit symmetric key
'''
algo = "AES-128-CMAC-VRF"
start = time.time()
ec.verify_auth_tag(algo,key,msg,nonce,AesCmacAuthTag)
log2(algo,key,msg,AesCmacAuthTag,nonce,start,time.time())

'''
SHA3-256-HMAC-GEN:
    128 bit symmetric key
'''
algo = "SHA3-256-HMAC-GEN"
nonce = nonces[4]
start = time.time()
Sha256AuthTag = ec.generate_auth_tag(algo,key,msg,nonce)
log2(algo,key,msg,Sha256AuthTag,nonce,start,time.time())

'''
SHA3-256-HMAC-VRF:
    128 bit symmetric key
'''
start = time.time()
algo = "SHA3-256-HMAC-VRF"
ec.verify_auth_tag(algo,key,msg,nonce,Sha256AuthTag)
log2(algo,key,msg,Sha256AuthTag,nonce,start,time.time())

'''
RSA-2048-SHA3-256-SIG-GEN:
    2048 bit public , private key pair
'''
algo = "RSA-2048-SHA3-256-SIG-GEN"
key = keys[4]
nonce = nonces[5]
start = time.time()
RsaSha256AuthTag =ec.generate_auth_tag(algo,key,msg,nonce)
log2(algo,key,msg,RsaSha256AuthTag,nonce,start,time.time())

'''
RSA-2048-SHA3-256-SIG-VRF:
    2048 bit public , private key pair
'''
algo = "RSA-2048-SHA3-256-SIG-VRF"
key = keys[3]
start = time.time()
ec.verify_auth_tag(algo,key,msg,nonce,RsaSha256AuthTag)
log2(algo,key,msg,RsaSha256AuthTag,nonce,start,time.time())

'''
ECDSA-256-SHA3-256-SIG-GEN:
    2048 bit public , private key pair
'''

start = time.time()
nonce = nonces[6]
key = keys[4]
algo = "ECDSA-256-SHA3-256-SIG-GEN"
start = time.time()
EcdsaSha256AuthTag =ec.generate_auth_tag(algo,key,msg,nonce)
log2(algo,key,msg,EcdsaSha256AuthTag,nonce,start,time.time())

'''
ECDSA-256-SHA3-256-SIG-VRF:
    2048 bit public , private key pair
'''
algo = "ECDSA-256-SHA3-256-SIG-VRF"
key = keys[3]
start = time.time()
ec.verify_auth_tag(algo,key,msg,nonce,EcdsaSha256AuthTag)
log2(algo,key,msg,EcdsaSha256AuthTag,nonce,start,time.time())

# Authentication,Encryption - Verification,Decryption Unit Test

def log3(algo,key1,key2,plain,cipher,auth_tag,nonce,start,end):
    print(algo +" time:", end-start,end='')
    print('s')
    print("Length of plaintext:",len(plain))
    print("Length of ciphertext:",len(cipher))
    if auth_tag:
        print("Length of auth_tag:",len(auth_tag))
    print("Length of key1:",len(key1))
    print("Length of key2:",len(key2))
    print("Length of nonce",len(nonce))

'''
AES-128-GCM-GEN:
    128 bit symmetric key
    2048 bit public , private key pair
'''
algo ="AES-128-GCM-GEN"
key1 = keys[0]
key2 = keys[5]
nonce = nonces[7]
start = time.time()
AesGcmCipher,AesGcmTag =ec.encrypt_generate_auth(algo,key,key2,msg,nonce)
log3(algo,key1,key2,msg,AesGcmCipher,AesGcmTag,nonce,start,time.time())
t = time.time()

'''
AES-128-GCM-VRF:
    128 bit symmetric key
    2048 bit public , private key pair
'''
algo = "AES-128-GCM-VRF"
key2 = keys[6]
start = time.time()
ec.decrypt_verify_auth(algo,key1,key2,AesGcmCipher,nonce,AesGcmTag)
log3(algo,key1,key2,msg,AesGcmCipher,AesGcmTag,nonce,start,time.time())