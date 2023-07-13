import os
import os
from hashlib import pbkdf2_hmac

#normal and inverse substitution boxes

s_box = (

    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inverse_s_box = (
    
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


#functions for substituting bytes using the s_boxes
def substitute_bytes(mat) -> None:

    for i in range(4):
        for j in range(4):
            mat[i][j] = s_box[mat[i][j]]


def inverse_substitute_bytes(mat) -> None:

    for i in range(4):
        for j in range(4):
            mat[i][j] = inverse_s_box[mat[i][j]]


#functions for shifting rows

def shift_rows(mat) -> None:

    mat[0][1], mat[1][1], mat[2][1], mat[3][1] = mat[1][1], mat[2][1], mat[3][1], mat[0][1]
    mat[0][2], mat[1][2], mat[2][2], mat[3][2] = mat[2][2], mat[3][2], mat[0][2], mat[1][2]
    mat[0][3], mat[1][3], mat[2][3], mat[3][3] = mat[3][3], mat[0][3], mat[1][3], mat[2][3]


def inverse_shift_rows(mat) -> None:

    mat[0][1], mat[1][1], mat[2][1], mat[3][1] = mat[3][1], mat[0][1], mat[1][1], mat[2][1]
    mat[0][2], mat[1][2], mat[2][2], mat[3][2] = mat[2][2], mat[3][2], mat[0][2], mat[1][2]
    mat[0][3], mat[1][3], mat[2][3], mat[3][3] = mat[1][3], mat[2][3], mat[3][3], mat[0][3]


#function for adding each round's key
def xor_round_key(mat, key) -> None:

    for i in range(4):
        for j in range(4):
            #XOR's each element
            mat[i][j] ^= key[i][j]


#XOR's all elements in two arrays and returns one byte array
def xor_bytes(arr1, arr2):
    return bytes(i^j for i, j in zip(arr1, arr2))


#round constant
round_const = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

#function to split text into blocks
def split_blocks(text):
        return [text[i:i+16] for i in range(0, len(text), 16)]


#function that converts an array of 16 bytes into a square matrix and reverse
def bytes_to_matrix(array):
    return [list(array[i:i+4]) for i in range(0, len(array), 4)]

def matrix_to_bytes(matrix):
    return bytes(sum(matrix, []))


#operation known as xtime used in the column mixing, it simulates multiplication and addition in the field
#between polynomials modulo another polynomial (too long to explain the actual math)
#implemented as shifting bits
xtime = lambda x: (((x << 1) ^ 0x1B) 
                        & 0xFF) if (x 
                            & 0x80) else (x << 1)


#function for mixing columns
def mix_columns(s):

    for i in range(4):

        xor_all = s[i][0] ^ s[i][1] ^ s[i][2] ^ s[i][3]
        first_copy = s[i][0]
        s[i][0] ^= xor_all ^ xtime(s[i][0] ^ s[i][1])
        s[i][1] ^= xor_all ^ xtime(s[i][1] ^ s[i][2])
        s[i][2] ^= xor_all ^ xtime(s[i][2] ^ s[i][3])
        s[i][3] ^= xor_all ^ xtime(s[i][3] ^ first_copy)


def inverse_mix_columns(s):
    
    for i in range(4):

        first_combination = xtime(xtime(s[i][0] ^ s[i][2]))
        second_combination = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= first_combination
        s[i][1] ^= second_combination
        s[i][2] ^= first_combination
        s[i][3] ^= second_combination

    mix_columns(s)


#pads the text to a length being a multiple of 16 bytes
def pad(text):

    padding_length = 16 - (len(text) % 16)
    padding = bytes([padding_length] * padding_length)
    return text + padding

#unpads a text after it was padded using the function above
def unpad(text):
    
    padding_length = text[-1]
    assert padding_length > 0
    message, padding = text[:-padding_length], text[-padding_length:]
    #assert all(p == padding_length for p in padding)
    return message


class AES:
    
    #different number of rounds depending on the key size
    possible_number_of_rounds = {16: 10, 24: 12, 32: 14}
    def __init__(self, key):
        
        #checks if key size is correct and initializes number of rounds and round keys
        assert len(key) in AES.possible_number_of_rounds
        self.rounds = AES.possible_number_of_rounds[len(key)]
        self.round_keys = self.expand_key(key)

    #creates each round's keys derived from the initial key
    def expand_key(self, key):
        
        #transform key into matrix containing each byte
        key_matrix = bytes_to_matrix(key)

        #initialize row size and iterator for traversing the matrix
        row_size = len(key) // 4
        i = 1
        #while iterating as many steps as the number of rounds
        while len(key_matrix) < (self.rounds + 1) * 4:

            #get previous row
            row = list(key_matrix[-1])

            #if start of row
            if len(key_matrix) % row_size == 0:
                
                #shift row circularly
                row.append(row.pop(0))
                #transform according to s-box
                row = [s_box[b] for b in row]
                # XOR first byte of row with first byte from respective row of the round constant
                row[0] ^= round_const[i]
                i += 1

            elif len(key) == 32 and len(key_matrix) % row_size == 4:

                #specific case for key of length 256
                row = [s_box[b] for b in row]

            # XOR current row with previous row
            row = xor_bytes(row, key_matrix[-row_size])
            key_matrix.append(row)

        #group resulting keys as matrices
        return [key_matrix[4*i : 4*(i+1)] for i in range(len(key_matrix) // 4)]


    #functions to encrypt and decrypt one single block of plain/cipher text

    def encrypt_block(self, plaintext):
        
        #check that block division was executed correctly
        assert len(plaintext) == 16

        #transform text into matrix 
        text_matrix = bytes_to_matrix(plaintext)

        #XOR with first round key
        xor_round_key(text_matrix, self.round_keys[0])

        #perform each necessary operation for each round
        for i in range(1, self.rounds):
            substitute_bytes(text_matrix)
            shift_rows(text_matrix)
            mix_columns(text_matrix)
            xor_round_key(text_matrix, self.round_keys[i])

        #perform last round's operations
        substitute_bytes(text_matrix)
        shift_rows(text_matrix)
        xor_round_key(text_matrix, self.round_keys[-1])

        #convert result to back to bytes
        return matrix_to_bytes(text_matrix)

    def decrypt_block(self, ciphertext):
        
        #opposite of above function, no further comments necessary
        assert len(ciphertext) == 16

        cipher_state = bytes_to_matrix(ciphertext)

        xor_round_key(cipher_state, self.round_keys[-1])
        inverse_shift_rows(cipher_state)
        inverse_substitute_bytes(cipher_state)

        for i in range(self.rounds - 1, 0, -1):
            xor_round_key(cipher_state, self.round_keys[i])
            inverse_mix_columns(cipher_state)
            inverse_shift_rows(cipher_state)
            inverse_substitute_bytes(cipher_state)

        xor_round_key(cipher_state, self.round_keys[0])

        return matrix_to_bytes(cipher_state)


    #encrypt and decrypt functions using pcbc mode
    def encrypt(self, plaintext, init_vector):
        
        #check correct length of initialization vector
        assert len(init_vector) == 16
        #pad text to necessary length
        padded_plaintext = pad(plaintext)
        encrypted_message = []
        #create variables for storing each block of plaintext and ciphertext after each round
        #initialize ciphertext with the initialization vector and plaintext with a default value
        last_ciphertext = init_vector
        last_plaintext = bytes(16)
        
        #iterate through each block of plaintext split accordingly
        for block in split_blocks(padded_plaintext):
            # the PCBC mode has the following rule of encryption:
            # first, XOR the previous plaintext and ciphertext
            # then, XOR the result with the current plaintext block
            encrypted_block = self.encrypt_block(xor_bytes(block, xor_bytes(last_ciphertext, last_plaintext)))
            #append current encrypted block to final result
            encrypted_message.append(encrypted_block)
            #modify variables accordingly
            last_ciphertext = encrypted_block
            last_plaintext = block

        #return encrypted message as byte string
        return b''.join(encrypted_message)

    def decrypt(self, ciphertext, init_vector):
        
        #won't repeat the same comments
        
        assert len(init_vector) == 16

        decrypted_message = []
        last_ciphertext = init_vector
        last_plaintext = bytes(16)

        for encrypted_block in split_blocks(ciphertext):
            # the PCBC mode has the following rule of decryption:
            # first, XOR the previous ciphertext and plaintext
            # then, XOR the result with the decyption of the current encrypted block 
            decrypted_block = xor_bytes(xor_bytes(last_ciphertext, last_plaintext), self.decrypt_block(encrypted_block))
            decrypted_message.append(decrypted_block)
            last_ciphertext = encrypted_block
            last_plaintext = decrypted_block

        #finally, unpad to remain with the initial sent message
        return unpad(b''.join(decrypted_message))

def create_initialization_vector(initial_key, salt):
    #derive the key using sha256 as the hashing algorithm
    #i've used parameter names to be more self explanatory
    #100000 iterations are recommended for sha256 as of 2022
    #dklen (the length of the derived key) is 32, since
    #we have 16 for the actual key and 16 for generating the initialization vector
    #values can be changed if you want to try another key size for AES
    derived_key = pbkdf2_hmac(hash_name='sha256', password=initial_key, 
                              salt=salt, iterations=100000, 
                              dklen=32)
    #get key
    key = derived_key[:16]
    #split derived key in half
    derived_key = derived_key[16:]
    #get initialization vector
    init_vector = derived_key[:16]

    return key, init_vector


#final encryption and decryption functions with salt

def encrypt(key, text):
    
    #encodes text using utf-8
    if isinstance(text, str):
        text = text.encode('utf-8')

    #generate salt of length 16
    salt = os.urandom(16)
    #generate key and initialization vector
    key, init_vector = create_initialization_vector(key, salt)
    
    ciphertext = AES(key).encrypt(text, init_vector)

    return salt + ciphertext


def decrypt(key, ciphertext, workload=100000):
    
    #check that encrypted text is made of 16 byte blocks
    #and that it is at least 32 bytes: 16 for salt and 16 for the minimum of one block
    assert len(ciphertext) % 16 == 0
    assert len(ciphertext) >= 32

    #slice appropriately to separate salt from ciphertext
    salt = ciphertext[:16]
    ciphertext = ciphertext[16:]
    key, init_vector = create_initialization_vector(key, salt)

    return AES(key).decrypt(ciphertext, init_vector)

def generate_key(length) -> int:
    return os.urandom(length)

def AES_keygen(length_arg):

    key = generate_key(int(length_arg))
    get_generations = open('../Utils/AES/generations.txt', 'r')
    generation = get_generations.read()
    get_generations.close()
    generation = str(int(generation)+1) 
    write_generations = open('../Utils/AES/generations.txt', 'w')
    write_generations.write(str(generation))
    write_generations.close()
    with open('../Utils/AES/key'+str(generation)+'.txt', 'wb') as f:
        f.write(key)
        f.close()
    print('Key generated')


def AES_encrypt(key_arg, plaintext_arg):

    get_generations = open('../Utils/AES/generations.txt', 'r')
    generation = get_generations.read()
    get_generations.close()

    key_file = open('../Utils/AES/'+key_arg, 'rb')
    key = key_file.read()
    key_file.close()

    plaintext_file = open('../Utils/AES/'+ plaintext_arg, 'r')
    plaintext = plaintext_file.read()
    plaintext_file.close()

    ciphertext = encrypt(key, plaintext)
    ciphertext_file = open('../Utils/AES/ciphertext'+str(generation)+'.txt', 'wb')
    ciphertext_file.write(ciphertext)
    ciphertext_file.close()

    print('Text encrypted')

def AES_decrypt(key_arg, ciphertext_arg):

    key_file = open('../Utils/AES/'+key_arg, 'rb')
    key = key_file.read()
    key_file.close()

    ciphertext_file = open('../Utils/AES/'+ciphertext_arg, 'rb')
    ciphertext = ciphertext_file.read()
    ciphertext_file.close()

    print(decrypt(key, ciphertext).decode('utf-8'))

__all__ = [AES_keygen, AES_encrypt, AES_decrypt, AES]