from functools import reduce
from Cryptodome.Random import get_random_bytes

#bitmasks for shifting
bitmask_8 = 0xFF
bitmask_32 = 0xFFFFFFFF
bitmask_64 = 0xFFFFFFFFFFFFFFFF
bitmask_128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
bitmask_192 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
bitmask_256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

#values to shift by in the subkeys step
val_1 = 0xA09E667F3BCC908B
val_2 = 0xB67AE8584CAA73B2
val_3 = 0xC6EF372FE94F82BE
val_4 = 0x54FF53A5F1D36F1C
val_5 = 0x10E527FADE682D1D
val_6 = 0xB05688C2B3E6C1FD

SBOX1 = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
    35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
    166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
    223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
    254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
    16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
    64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158
]
progress = 0


class Camellia:
    def __init__(self, key, is_decrypt=False):
          
        self.key_size = len(key)

        if self.key_size not in [16, 24, 32]:
            raise ValueError("Key size not right")
        
        #convert bytes to integer
        self._key = int.from_bytes(key, byteorder='little')

        #split key into left and right half
        key_l, key_r = self.split_key(self._key)

        #compute helper variables KA and KB 
        key_a, key_b = self.compute_helpers(key_l, key_r)

        #split into necessary keys for next step
        #aka KL, KR, KA, KB -> KW, K, to_apply
        self.key_w, self.k, self.key_e = self.generate_keys(key_l, key_r, key_a, key_b, is_decrypt)

    def encrypt_block(self, block):

        block = int.from_bytes(block, byteorder='little')

        # apply number of rounds according to feistel network (either 18 or 24 depending on key size)


        #divide message into two halves 
        left_side = block >> 64  
        right_side = block & bitmask_64

        #key whitening
        left_side = left_side ^ self.key_w[0] & bitmask_64  
        right_side = right_side ^ self.key_w[1] & bitmask_64

        #apply functions f and FInv according to algorithm
        right_side = right_side ^ self.f(left_side, self.k[0]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[1]) & bitmask_64
        right_side = right_side ^ self.f(left_side, self.k[2]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[3]) & bitmask_64
        right_side = right_side ^ self.f(left_side, self.k[4]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[5]) & bitmask_64

        left_side = self.fl(left_side, self.key_e[0]) & bitmask_64 
        right_side = self.fl_inv(right_side, self.key_e[1]) & bitmask_64 

        right_side = right_side ^ self.f(left_side, self.k[6]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[7]) & bitmask_64
        right_side = right_side ^ self.f(left_side, self.k[8]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[9]) & bitmask_64
        right_side = right_side ^ self.f(left_side, self.k[10]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[11]) & bitmask_64

        left_side = self.fl(left_side, self.key_e[2]) & bitmask_64  
        right_side = self.fl_inv(right_side, self.key_e[3]) & bitmask_64  

        right_side = right_side ^ self.f(left_side, self.k[12]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[13]) & bitmask_64
        right_side = right_side ^ self.f(left_side, self.k[14]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[15]) & bitmask_64
        right_side = right_side ^ self.f(left_side, self.k[16]) & bitmask_64
        left_side = left_side ^ self.f(right_side, self.k[17]) & bitmask_64

        if self.key_size != 16:

            left_side = self.fl(left_side, self.key_e[4]) & bitmask_64  
            right_side = self.fl_inv(right_side, self.key_e[5]) & bitmask_64  

            right_side = right_side ^ self.f(left_side, self.k[18]) & bitmask_64
            left_side = left_side ^ self.f(right_side, self.k[19]) & bitmask_64
            right_side = right_side ^ self.f(left_side, self.k[20]) & bitmask_64
            left_side = left_side ^ self.f(right_side, self.k[21]) & bitmask_64
            right_side = right_side ^ self.f(left_side, self.k[22]) & bitmask_64
            left_side = left_side ^ self.f(right_side, self.k[23]) & bitmask_64

        right_side = right_side ^ self.key_w[2] & bitmask_64  # Финальное забеливание
        left_side = left_side ^ self.key_w[3] & bitmask_64

        encrypted = ((right_side << 64) | left_side) & bitmask_128

        return encrypted.to_bytes(self.key_size, byteorder='little')[:16]

    # function to split key into two halves
    # depending on the key size
    def split_key(self, key):

        if self.key_size == 16:
            return key, 0
        
        elif self.key_size == 24:
            return key >> 64, (((key & bitmask_64) << 64) | (~(key & bitmask_64))) & bitmask_128
        
        return key >> 128, key & bitmask_128

    def compute_helpers(self, key_l, key_r):

        left_side = (key_l ^ key_r) >> 64
        right_side = (key_l ^ key_r) & bitmask_64

        right_side = right_side ^ self.f(left_side, val_1)
        left_side = left_side ^ self.f(right_side, val_2)

        left_side = left_side ^ (key_l >> 64)
        right_side = right_side ^ (key_l & bitmask_64)

        right_side = right_side ^ self.f(left_side, val_3)
        left_side = left_side ^ self.f(right_side, val_4)

        key_a = ((left_side << 64) & bitmask_128) | right_side

        left_side = (key_a ^ key_r) >> 64
        right_side = (key_a ^ key_r) & bitmask_64

        right_side = right_side ^ self.f(left_side, val_5)
        left_side = left_side ^ self.f(right_side, val_6)

        key_b = ((left_side << 64) & bitmask_128) | right_side

        return key_a, key_b

    def generate_keys(self, key_l, key_r, key_a, key_b, is_decrypt=False):

        if self.key_size == 16:
            
            key_w = [0] * 4
            k = [0] * 18
            key_e = [0] * 4

            key_w[0] = self.shift_bytes(key_l, 0, 128) >> 64
            key_w[1] = self.shift_bytes(key_l, 0, 128) & bitmask_64

            k[0] = self.shift_bytes(key_a, 0, 128) >> 64
            k[1] = self.shift_bytes(key_a, 0, 128) & bitmask_64
            k[2] = self.shift_bytes(key_l, 15, 128) >> 64
            k[3] = self.shift_bytes(key_l, 15, 128) & bitmask_64
            k[4] = self.shift_bytes(key_a, 15, 128) >> 64
            k[5] = self.shift_bytes(key_a, 15, 128) & bitmask_64

            key_e[0] = self.shift_bytes(key_a, 30, 128) >> 64
            key_e[1] = self.shift_bytes(key_a, 30, 128) & bitmask_64

            k[6] = self.shift_bytes(key_l, 45, 128) >> 64
            k[7] = self.shift_bytes(key_l, 45, 128) & bitmask_64
            k[8] = self.shift_bytes(key_a, 45, 128) >> 64
            k[9] = self.shift_bytes(key_l, 60, 128) & bitmask_64
            k[10] = self.shift_bytes(key_a, 60, 128) >> 64
            k[11] = self.shift_bytes(key_a, 60, 128) & bitmask_64

            key_e[2] = self.shift_bytes(key_l, 77, 128) >> 64
            key_e[3] = self.shift_bytes(key_l, 77, 128) & bitmask_64

            k[12] = self.shift_bytes(key_l, 94, 128) >> 64
            k[13] = self.shift_bytes(key_l, 94, 128) & bitmask_64
            k[14] = self.shift_bytes(key_a, 94, 128) >> 64
            k[15] = self.shift_bytes(key_a, 94, 128) & bitmask_64
            k[16] = self.shift_bytes(key_l, 111, 128) >> 64
            k[17] = self.shift_bytes(key_l, 111, 128) & bitmask_64

            key_w[2] = self.shift_bytes(key_a, 111, 128) >> 64
            key_w[3] = self.shift_bytes(key_a, 111, 128) & bitmask_64
            
            if is_decrypt:
                
                key_w[0], key_w[2] = key_w[2], key_w[0]
                key_w[1], key_w[3] = key_w[3], key_w[1]

                k[0], k[17] = k[17], k[0]
                k[1], k[16] = k[16], k[1]
                k[2], k[15] = k[15], k[2]
                k[3], k[14] = k[14], k[3]
                k[4], k[13] = k[13], k[4]
                k[5], k[12] = k[12], k[5]
                k[6], k[11] = k[11], k[6]
                k[7], k[10] = k[10], k[7]
                k[8], k[9] = k[9], k[8]

                key_e[0], key_e[3] = key_e[3], key_e[0]
                key_e[1], key_e[2] = key_e[2], key_e[1]
        else:
            
            key_w = [0] * 4
            k = [0] * 24
            key_e = [0] * 6

            key_w[0] = self.shift_bytes(key_l, 0, 128) >> 64
            key_w[1] = self.shift_bytes(key_l, 0, 128) & bitmask_64

            k[0] = self.shift_bytes(key_b, 0, 128) >> 64
            k[1] = self.shift_bytes(key_b, 0, 128) & bitmask_64
            k[2] = self.shift_bytes(key_r, 15, 128) >> 64
            k[3] = self.shift_bytes(key_r, 15, 128) & bitmask_64
            k[4] = self.shift_bytes(key_a, 15, 128) >> 64
            k[5] = self.shift_bytes(key_a, 15, 128) & bitmask_64

            key_e[0] = self.shift_bytes(key_r, 30, 128) >> 64
            key_e[1] = self.shift_bytes(key_r, 30, 128) & bitmask_64

            k[6] = self.shift_bytes(key_b, 30, 128) >> 64
            k[7] = self.shift_bytes(key_b, 30, 128) & bitmask_64
            k[8] = self.shift_bytes(key_l, 45, 128) >> 64
            k[9] = self.shift_bytes(key_l, 45, 128) & bitmask_64
            k[10] = self.shift_bytes(key_a, 45, 128) >> 64
            k[11] = self.shift_bytes(key_a, 45, 128) & bitmask_64

            key_e[2] = self.shift_bytes(key_l, 60, 128) >> 64
            key_e[3] = self.shift_bytes(key_l, 60, 128) & bitmask_64

            k[12] = self.shift_bytes(key_r, 60, 128) >> 64
            k[13] = self.shift_bytes(key_r, 60, 128) & bitmask_64
            k[14] = self.shift_bytes(key_b, 60, 128) >> 64
            k[15] = self.shift_bytes(key_b, 60, 128) & bitmask_64
            k[16] = self.shift_bytes(key_l, 77, 128) >> 64
            k[17] = self.shift_bytes(key_l, 77, 128) & bitmask_64

            key_e[4] = self.shift_bytes(key_a, 77, 128) >> 64
            key_e[5] = self.shift_bytes(key_a, 77, 128) & bitmask_64

            k[18] = self.shift_bytes(key_r, 94, 128) >> 64
            k[19] = self.shift_bytes(key_r, 94, 128) & bitmask_64
            k[20] = self.shift_bytes(key_a, 94, 128) >> 64
            k[21] = self.shift_bytes(key_a, 94, 128) & bitmask_64
            k[22] = self.shift_bytes(key_l, 111, 128) >> 64
            k[23] = self.shift_bytes(key_l, 111, 128) & bitmask_64

            key_w[2] = self.shift_bytes(key_b, 111, 128) >> 64
            key_w[3] = self.shift_bytes(key_b, 111, 128) & bitmask_64

            if is_decrypt:
                
                key_w[0], key_w[2] = key_w[2], key_w[0]
                key_w[1], key_w[3] = key_w[3], key_w[1]

                k[0], k[23] = k[23], k[0]
                k[1], k[22] = k[22], k[1]
                k[2], k[21] = k[21], k[2]
                k[3], k[20] = k[20], k[3]
                k[4], k[19] = k[19], k[4]
                k[5], k[18] = k[18], k[5]
                k[6], k[17] = k[17], k[6]
                k[7], k[16] = k[16], k[7]
                k[8], k[15] = k[15], k[8]
                k[9], k[14] = k[14], k[9]
                k[10], k[13] = k[13], k[10]
                k[11], k[12] = k[12], k[11]

                key_e[0], key_e[5] = key_e[5], key_e[0]
                key_e[1], key_e[4] = key_e[4], key_e[1]
                key_e[2], key_e[3] = key_e[3], key_e[2]

        return key_w, k, key_e

    #function to shift size by a value used throughout the whole code
    def shift_bytes(self, num, shift, num_size):

        shift = shift % num_size
        return ((num << shift) | (num >> (num_size - shift))) & ((1 << num_size) - 1)

    #function f according to cipher
    def f(self, func_input, to_apply):
        
        x = func_input ^ to_apply

        t1 = (x >> 56) & bitmask_8
        t2 = (x >> 48) & bitmask_8
        t3 = (x >> 40) & bitmask_8
        t4 = (x >> 32) & bitmask_8
        t5 = (x >> 24) & bitmask_8
        t6 = (x >> 16) & bitmask_8
        t7 = (x >> 8) & bitmask_8
        t8 = x & bitmask_8

        t1 = SBOX1[t1] & bitmask_8
        t2 = self.shift_bytes(SBOX1[t2], 1, 8) & bitmask_8
        t3 = self.shift_bytes(SBOX1[t3], 7, 8) & bitmask_8
        t4 = SBOX1[self.shift_bytes(t4, 1, 8)] & bitmask_8
        t5 = self.shift_bytes(SBOX1[t5], 1, 8) & bitmask_8
        t6 = self.shift_bytes(SBOX1[t6], 7, 8) & bitmask_8
        t7 = SBOX1[self.shift_bytes(t7, 1, 8)] & bitmask_8
        t8 = SBOX1[t8] & bitmask_8

        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7

        func_value = (y1 << 56) | (y2 << 48) | (y3 << 40) | (
                y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8

        return func_value

    #function fl according to cipher
    def fl(self, func_input, to_apply):
        
        x1 = func_input >> 32
        x2 = func_input & bitmask_32
        k1 = to_apply >> 32
        k2 = to_apply & bitmask_32
        x2 = x2 ^ self.shift_bytes(x1 & k1, 1, 32)
        x1 = x1 ^ (x2 | k2)
        output = (x1 << 32) | x2
        return output

    #functin fl inverse according to cipher
    def fl_inv(self, FLINV_IN, to_apply):
        
        y1 = FLINV_IN >> 32
        y2 = FLINV_IN & bitmask_32
        k1 = to_apply >> 32
        k2 = to_apply & bitmask_32
        y1 = y1 ^ (y2 | k2)
        y2 = y2 ^ self.shift_bytes(y1 & k1, 1, 32)
        output = (y1 << 32) | y2
        return output

#function to xor two byte arrays
def xor_bytes(a, b, size):
    return (int.from_bytes(a, byteorder='little') ^ int.from_bytes(b, byteorder='little')) \
        .to_bytes(size, byteorder='little')

#i know ECB is bad, I really do
#this code took a toll on me though and I decided to remain with ECB
#and not complicate things further with CBC
#i know how bad it is tho
class ECB:
    
	def __init__(self, camellia):
                
		self.camellia = camellia
		self.bs = 16

	def encrypt(self, b_arr):
                
		blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]
        
		ciphertext = []
		for block in blocks:
			ciphertext.append(self.camellia.encrypt_block(block))
                        
		return ciphertext
            
		

	def decrypt(self, b_arr):
                
		blocks = [b_arr[i: i + self.bs] for i in range(0, len(b_arr), self.bs)]

		plaintext = []
		for block in blocks:
			plaintext.append(self.camellia.encrypt_block(block))
                        
		return plaintext

def generate_key(length) -> int:

    return get_random_bytes(length)

def Camellia_keygen(length_arg):
     
    key = generate_key(int(length_arg))
    get_generations = open('../Utils/Camellia/generations.txt', 'r')
    generation = get_generations.read()
    get_generations.close()
    generation = str(int(generation)+1) 
    write_generations = open('../Utils/Camellia/generations.txt', 'w')
    write_generations.write(str(generation))
    write_generations.close()
    with open('../Utils/Camellia/key'+str(generation)+'.txt', 'wb') as f:
        f.write(key)
        f.close()
    print('Key generated')

    return

def Camellia_encrypt(key_arg, plaintext_arg):
     
    get_generations = open('../Utils/Camellia/generations.txt', 'r')
    generation = get_generations.read()
    get_generations.close()

    key_file = open('../Utils/Camellia/'+key_arg, 'rb')
    key = key_file.read()
    key_file.close()

    plaintext_file = open('../Utils/Camellia/'+ plaintext_arg, 'r')
    plaintext = plaintext_file.read()
    plaintext_file.close()

    camellia_encrypt = Camellia(key, False)
    ecb_encrypt = ECB(camellia_encrypt)
    ciphertext = ecb_encrypt.encrypt(bytes(plaintext, 'utf-8'))
    text = reduce(lambda a,b: a+b, ciphertext)
    ciphertext_file = open('../Utils/Camellia/ciphertext'+str(generation)+'.txt', 'wb')
    ciphertext_file.write(text)
    ciphertext_file.close()
    
    print('Text encrypted')

def Camellia_decrypt(key_arg, ciphertext_arg):
     
    key_file = open('../Utils/Camellia/'+key_arg, 'rb')
    key = key_file.read()
    key_file.close()

    ciphertext_file = open('../Utils/Camellia/'+ciphertext_arg, 'rb')
    ciphertext = ciphertext_file.read()
    ciphertext_file.close()

    camellia_decrypt = Camellia(key, True)
    ecb_decrypt = ECB(camellia_decrypt)
    plaintext = ecb_decrypt.decrypt(ciphertext)
    final_text = (reduce(lambda a,b: a+b, plaintext)).decode('utf-8')
    print(final_text)

__all__ = [Camellia_keygen, Camellia_encrypt, Camellia_decrypt, Camellia]


    
	
        
	
	
                
	