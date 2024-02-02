import pyaes

texts = [
    (b'abcdefghijklmno',b'WY\xa1\xb4\xfa\x86^Mu\x9a\x8c\x0b\xb1\x18\xd9'),
]

def crack(texts):
    iterations = 0
    N = 2**16
    for key in range(N):
        iterations += 1
        keystream = key.to_bytes(16,byteorder='big')
        passAll = True
        for plaintext,ciphertext in texts:
            decrypted = pyaes.AESModeOfOperationCTR(keystream).decrypt(ciphertext)
            if decrypted != plaintext:
                passAll = False
        if (passAll):
            return(key,iterations)
            return
    print("Failure!")
crack(texts)