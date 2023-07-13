import AES, Camellia, ElGamal
import sys

if __name__ == '__main__':

    if len(sys.argv) > 3:

        match(sys.argv[1]):
            #the generations file will have an int in it (0 by default)
            #and when generating a key and encrypting, it will create the file according to that int
            #for example, for the first generation of keys and encryption, these files will get generated
            #key1.txt, ciphertext1.txt
            #now, if you generate another key, it will be: key2.txt and etc
            #keep in mind that ElGamal generates two keys instead of 1, but still according to the generations file

            #example of aes
            #key generation: python3 main.py AES keygen 16 (16 is the number of bytes for the key)
            #encrypt: python3 main.py AES encrypt key1.txt plaintext.txt
            #decrypt: python3 main.py AES decrypt key1.txt ciphertext1.txt
            case 'AES':
                if len(sys.argv) == 4:
                    AES.AES_keygen(sys.argv[3])
                elif len(sys.argv) == 5 and 'encrypt'.startswith(sys.argv[2]):
                    AES.AES_encrypt(sys.argv[3], sys.argv[4])
                elif len(sys.argv) == 5 and 'decrypt'.startswith(sys.argv[2]):
                    AES.AES_decrypt(sys.argv[3], sys.argv[4])

            #example of Camellia
            #key generation: python3 main.py Camellia keygen 16 (16 is the number of bytes for the key)
            #encrypt: python3 main.py Camellia encrypt key1.txt plaintext.txt
            #decrypt: python3 main.py Camellia decrypt key1.txt ciphertext1.txt
            case 'Camellia':
                if len(sys.argv) == 4:
                    Camellia.Camellia_keygen(sys.argv[3])
                elif len(sys.argv) == 5 and 'encrypt'.startswith(sys.argv[2]):
                    Camellia.Camellia_encrypt(sys.argv[3], sys.argv[4])
                elif len(sys.argv) == 5 and 'decrypt'.startswith(sys.argv[2]):
                    Camellia.Camellia_decrypt(sys.argv[3], sys.argv[4])

            case 'ElGamal':
            #example of ElGamal
            #key generation: python3 main.py ElGamal keygen 128 32 (128 is the maximum prime, 32 is the nb of steps to try to find the number probabilistically)
            #encrypt: python3 main.py ElGamal encrypt public_key1.pk1 plaintext.txt
            #decrypt: python3 main.py ElGamal decrypt private_key.pk1 ciphertext1.txt
                if len(sys.argv) == 5 and 'keygen'.startswith(sys.argv[2]):
                    ElGamal.ElGamal_keygen(int(sys.argv[3]), int(sys.argv[4]))
                elif len(sys.argv) == 5 and 'encrypt'.startswith(sys.argv[2]):
                    ElGamal.ElGamal_encrypt(sys.argv[3], sys.argv[4])
                elif len(sys.argv) == 5 and 'decrypt'.startswith(sys.argv[2]):
                    ElGamal.ElGamal_decrypt(sys.argv[3], sys.argv[4])




