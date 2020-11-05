from socket import socket
import iv as iv
from Crypto.Cipher import AES

s = socket()
s.connect(("localhost",15000))
s.send()

K = b'128 byte key'
K1 = b'128 byte key' #Am notat cheia k' cu k1
iv = generate_random_key(K,K1)

def xor(A,B):
    assert len(A) >= len(B)
    return "".join([chr( ord(A[i]) ^ ord(B[i])) for i in range(len(A))])

def generate_random_key():
    rnd = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    return rnd

data=b'Modul de operare folosit este CBC'
def do_encrypt(data):
    cipher1 = AES.new(K1, AES.MODE_CBC, iv)
    ciphertext = cipher1.encrypt(data)
    return ciphertext

def do_decrypt(ciphertext):
    cipher1 = AES.new(K, AES.MODE_CBC, iv)
    data = cipher1.decrypt(ciphertext)
    return data

file_to_encrypt = 'my_file.txt'
buffer_size = 65536

#Deschidem fisierele input si output
input_file = open(file_to_encrypt, 'rb')
output_file = open(file_to_encrypt + '.encrypted', 'wb')

#Creeam obiectul de criptare si criptam data
cipher_encrypt = AES.new(K, AES.MODE_CBC)

#Initial scriem iv-ul in fisierul output
output_file.write(cipher_encrypt.iv)

#Citim fisierul intr-un buffer , il criptam si il scriem in fisierul nou
buffer = input_file.read(buffer_size)
while len(buffer) > 0:
    ciphered_bytes = cipher_encrypt.encrypt(buffer)
    output_file.write(ciphered_bytes)
    buffer = input_file.read(buffer_size)

#Inchidem input si output
input_file.close()
output_file.close()

if __name__ == '__main__':
    test_crypto()