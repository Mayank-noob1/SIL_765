import pyaes
L = list()

for i in range(256):
    for j in range(256):
        if ((bin(i)[2:].count('1')+bin(j)[2:].count('1')) == 8):
            L.append((i,j))

texts = [
    (b'abcdefghijklmno',b'WY\xa1\xb4\xfa\x86^Mu\x9a\x8c\x0b\xb1\x18\xd9'),
]

def crack():
    iterations = 0
    for (i1,i2) in L:
        iterations += 1
        key = 256*i1 +i2
        keystream = key.to_bytes(16,byteorder='big')
        passAll = True
        for plaintext,ciphertext in texts:
            decrypted = pyaes.AESModeOfOperationCTR(keystream).decrypt(ciphertext)
            if decrypted != plaintext:
                passAll = False
        if (passAll):
            print(key,iterations)
            return
    print("Failure!")
crack()