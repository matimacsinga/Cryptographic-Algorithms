import random
import pickle

class Private_Key(object):

	def __init__(self, p=None, g=None, x=None, nb_of_bits=0):
		self.p = p
		self.g = g
		self.x = x
		self.nb_of_bits = nb_of_bits

class Public_Key(object):
	
	def __init__(self, p=None, g=None, h=None, nb_of_bits=0):
		self.p = p
		self.g = g
		self.h = h
		self.nb_of_bits = nb_of_bits


def greatest_common_divisor( a, b ):
		#start with a > b
		while b != 0:
			c = a % b
			a = b
			b = c
		#if b is 0, that means a is divisible by it, so we are done
		return a

#does the operation base ^ exponent % modulo
def modular_exponentiation( base, exponent, modulo ):
		
		return pow(base, exponent, modulo)

#check if number is prime with the solovay-strassen method
def is_prime( nb, steps ):
		
		#run for nb of steps
		for i in range(steps):
				
				#choose a random number in the range 1 and nb-1
				a = random.randint( 1, nb-1 )

				#check if a and nb relatively prime to each other
				if greatest_common_divisor( a, nb ) > 1:
						return False

				#check method rule: jacobi symbol congruence
				if not compute_jacobi_symbol( a, nb ) % nb == modular_exponentiation ( a, (nb-1)//2, nb ):
						return False

		#if none of the checks go through during the steps, the number is PROBABLY prime
		return True

#compute the jacobi symbol of a and n
def compute_jacobi_symbol( a, n ):
		
		#special cases
		if a == 0:
				if n == 1:
						return 1
				else:
						return 0
		
		elif a == -1:
				if n % 2 == 0:
						return 1
				else:
						return -1
		
		elif a == 1:
				return 1
		
		elif a == 2:
				if n % 8 == 1 or n % 8 == 7:
						return 1
				elif n % 8 == 3 or n % 8 == 5:
						return -1
		
		#normal cases
		elif a >= n:
				return compute_jacobi_symbol( a%n, n)
		elif a%2 == 0:
				return compute_jacobi_symbol(2, n)*compute_jacobi_symbol(a//2, n)
		else:
				if a % 4 == 3 and n%4 == 3:
						return -1 * compute_jacobi_symbol( n, a)
				else:
						return compute_jacobi_symbol(n, a )


#find a primitive root of p
def get_primitive_root( prime ):
		if prime == 2:
				return 1
		#since the nb is prime, its prime divisors are the following:
		prime_divisor1 = 2
		prime_divisor2 = (prime-1) // prime_divisor1

		#test random g's until one is found that is a primitive root mod p
		while( 1 ):
				g = random.randint( 2, prime-1 )
				#check if g is as primitive root of prime
				if not (modular_exponentiation( g, (prime-1)//prime_divisor1, prime ) == 1):
						if not modular_exponentiation( g, (prime-1)//prime_divisor2, prime ) == 1:
								return g

#find prime number of specified bits
def get_prime(nb_of_bits, steps):
		
		while(1):
				#try to find prime number randomly
				prime = random.randint( 2**(nb_of_bits-2), 2**(nb_of_bits-1))

				#quick check parity
				while( prime % 2 == 0 ):
						prime = random.randint(2**(nb_of_bits-2),2**(nb_of_bits-1))

				#repeat steps if not prime
				while( not is_prime(prime, steps) ):
						prime = random.randint( 2**(nb_of_bits-2), 2**(nb_of_bits-1) )
						while( prime % 2 == 0 ):
								prime = random.randint(2**(nb_of_bits-2), 2**(nb_of_bits-1))

				
				prime = prime * 2 + 1
				if is_prime(prime, steps):
						return prime

#converts bytes to an array of integers modulo p
def bytes_to_int_mod(plaintext, nb_of_bits):
		
		encoded_bytes = bytearray(plaintext, 'utf-16')

		arr = []

		#each integer will be made up of p bytes
		#floor by 8 since 1 byte is 8 bits obv
		p = nb_of_bits//8

		#iterator for each integer
		#to iterate to the next integer, it jumps p bits
		j = -1 * p

		#iterate byte array
		for i in range( len(encoded_bytes) ):
				#if divisible, jump to next integer
				if i % p == 0:
						j += p
						arr.append(0)
				#add to array by converting into integer
				arr[j//p] += encoded_bytes[i]*(2**(8*(i%p)))

		return arr

#reverse of above function, won't fill with comments twice
def int_mod_to_bytes(plaintext, nb_of_bits):
		
		bytes_arr = []

		p = nb_of_bits//8

		for nb in plaintext:
				for i in range(p):
						
						temp_nb = nb
						for j in range(i+1, p):
								
								temp_nb = temp_nb % (2**(8*j))
						
						letter = temp_nb // (2**(8*i))
						
						bytes_arr.append(letter)
						
						nb = nb - (letter*(2**(8*i)))

		decoded_bytes = bytearray(b for b in bytes_arr).decode('utf-16')

		return decoded_bytes

def generate_keys(nb_of_bits=256, steps=32):
		#variable names according to actual names from description of algorithm
		p = get_prime(nb_of_bits, steps)
		g = get_primitive_root(p)
		g = modular_exponentiation( g, 2, p )
		x = random.randint( 1, (p - 1) // 2 )
		h = modular_exponentiation( g, x, p )
		public_key = Public_Key(p, g, h, nb_of_bits)
		private_key = Private_Key(p, g, x, nb_of_bits)
		#these will be stored in the files
		return {'private_key': private_key, 'public_key': public_key}


def encrypt(key, plaintext):
		#even more math, nothing special
		#just did everything according to the steps
		integers = bytes_to_int_mod(plaintext, key.nb_of_bits)

		pairs = []
		
		for i in integers:
				
				y = random.randint( 0, key.p )
				c = modular_exponentiation( key.g, y, key.p )
				d = (i*modular_exponentiation( key.h, y, key.p)) % key.p
				pairs.append( [c, d] )

		ciphertext = ""

		for pair in pairs:
				ciphertext += str(pair[0]) + ' ' + str(pair[1]) + ' '
	
		return ciphertext

def decrypt(key, cipher):
		#math math math math
		plaintext = []

		array_from_text = cipher.split()

		for i in range(0, len(array_from_text), 2):
				
				c = int(array_from_text[i])
				d = int(array_from_text[i+1])
				s = modular_exponentiation( c, key.x, key.p )
				plain_sequence = (d*modular_exponentiation( s, key.p-2, key.p)) % key.p
				plaintext.append( plain_sequence )

		final_text = int_mod_to_bytes(plaintext, key.nb_of_bits)

		final_text = "".join([ch for ch in final_text if ch != '\x00'])

		return final_text

def ElGamal_keygen(length_arg, confidence_arg):

	get_generations = open('../Utils/ElGamal/generations.txt', 'r')
	generation = get_generations.read()
	get_generations.close()
	generation = str(int(generation)+1) 
	write_generations = open('../Utils/ElGamal/generations.txt', 'w')
	write_generations.write(str(generation))
	write_generations.close()

	keys = generate_keys(length_arg, confidence_arg)
	private_key = keys['private_key']
	public_key = keys['public_key']
	private_key_file = open('../Utils/ElGamal/private_key'+generation+'.pk1', 'wb')
	public_key_file = open('../Utils/ElGamal/public_key'+generation+'.pk1', 'wb')
	pickle.dump(public_key, public_key_file, pickle.HIGHEST_PROTOCOL)
	pickle.dump(private_key, private_key_file, pickle.HIGHEST_PROTOCOL)
	private_key_file.close()
	public_key_file.close()

	print('Key Generated')

def ElGamal_encrypt(public_key_arg, plaintext_arg):

	get_generations = open('../Utils/ElGamal/generations.txt', 'r')
	generation = get_generations.read()
	get_generations.close()

	key_file = open('../Utils/ElGamal/'+public_key_arg, 'rb')
	key = pickle.load(key_file)
	key_file.close()

	plaintext_file = open('../Utils/ElGamal/'+ plaintext_arg, 'r')
	plaintext = plaintext_file.read()
	plaintext_file.close()	

	ciphertext = encrypt(key, plaintext)
	ciphertext_file = open('../Utils/ElGamal/ciphertext'+generation+'.txt', 'w')
	ciphertext_file.write(ciphertext)
	ciphertext_file.close()
	print('Text Encrypted')

def ElGamal_decrypt(private_key_arg, ciphertext_arg):

	key_file = open('../Utils/ElGamal/'+private_key_arg, 'rb')
	key = pickle.load(key_file)
	key_file.close()

	ciphertext_file = open('../Utils/ElGamal/'+ciphertext_arg, 'r')
	ciphertext = ciphertext_file.read()
	ciphertext_file.close()

	print(decrypt(key, ciphertext))

__all__ = [ElGamal_keygen, ElGamal_encrypt, ElGamal_decrypt]
