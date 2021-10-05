#!/usr/bin/env python
# ******************************************************************************
# DES.py
#
# DES Encryption/Decryption Algorithm
# ******************************************************************************

import argparse

permute_key56 = [ 57, 49, 41, 33, 25, 17,  9,
				   1, 58, 50, 42, 34, 26, 18,
				  10,  2, 59, 51, 43, 35, 27,
				  19, 11,  3, 60, 52, 44, 36,
				  63, 55, 47, 39, 31, 23, 15,
				   7, 62, 54, 46, 38, 30, 22,
				  14,  6, 61, 53, 45, 37, 29,
				  21, 13,  5, 28, 20, 12,  4 ]
				
permute_key48 = [ 14, 17, 11, 24,  1,  5,
				   3, 28, 15,  6, 21, 10,
				  23, 19, 12,  4, 26,  8,
				  16,  7, 27, 20, 13,  2,
				  41, 52, 31, 37, 47, 55,
				  30, 40, 51, 45, 33, 48,
				  44, 49, 39, 56, 34, 53,
				  46, 42, 50, 36, 29, 32 ]
				
init_permute  = [ 58, 50, 42, 34, 26, 18, 10,  2,
				  60, 52, 44, 36, 28, 20, 12,  4,
				  62, 54, 46, 38, 30, 22, 14,  6,
				  64, 56, 48, 40, 32, 24, 16,  8,
				  57, 49, 41, 33, 25, 17,  9,  1,
				  59, 51, 43, 35, 27, 19, 11,  3,
				  61, 53, 45, 37, 29, 21, 13,  5,
				  63, 55, 47, 39, 31, 23, 15,  7 ]

e_bit_table   = [ 32,  1,  2,  3,  4,  5,
				   4,  5,  6,  7,  8,  9,
				   8,  9, 10, 11, 12, 13,
				  12, 13, 14, 15, 16, 17,
				  16, 17, 18, 19, 20, 21,
				  20, 21, 22, 23, 24, 25,
				  24, 25, 26, 27, 28, 29,
				  28, 29, 30, 31, 32,  1 ]
				  
s1 = [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
	  [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
	  [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
	  [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]]
	  
p  = [16,  7, 20, 21,
	  29, 12, 28, 17,
	   1, 15, 23, 26,
	   5, 18, 31, 10,
	   2,  8, 24, 14,
	  32, 27,  3,  9,
	  19, 13, 30,  6,
	  22, 11,  4, 25 ]

ip_inverse = [40,  8, 48, 16, 56, 24, 64, 32,
			  39,  7, 47, 15, 55, 23, 63, 31,
			  38,  6, 46, 14, 54, 22, 62, 30,
			  37,  5, 45, 13, 53, 21, 61, 29,
			  36,  4, 44, 12, 52, 20, 60, 28,
			  35,  3, 43, 11, 51, 19, 59, 27,
			  34,  2, 43, 10, 50, 18, 58, 26,
			  33,  1, 41,  9, 49, 17, 57, 25 ]

shift_num = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
	
def generate_subkeys():
	# hardcoded key
	key = 0x133457799bbcdff1
	key = format(key, '#066b')
	
	# convert key to 56-bit 
	key56 = '0b'
	for c in permute_key56:
		key56 = key56 + key[int(c)+1]
		
	# split left/right keys
	left_key  = key56[:30]
	right_key = '0b' + key56[30:66]
	
	left_blocks  = []
	right_blocks = []
	
	for n in range(16):
		left_key, right_key = shift_key(left_key, right_key, shift_num[n])
		left_blocks  += [left_key]
		right_blocks += [right_key]
	
	permuted_keys = []
	
	for n in range(16):
		combined_str = left_blocks[n][2:] + right_blocks[n][2:]
		key48 = '0b'
		for c in permute_key48:
			key48 = key48 + combined_str[int(c)-1]
		permuted_keys += [key48]
	
	return permuted_keys

def shift_key(left_key, right_key, shift):
	left_key  = '0b' + left_key[2+shift:30] + left_key[2:2+shift]
	right_key = '0b' + right_key[2+shift:30] + right_key[2:2+shift]
	
	return left_key, right_key
	
def decode(ciphertext, permuted_keys):
	ciphertext = format(ciphertext, '#066b')
	plaintext = ''
	ip = '0b'
	
	for c in init_permute:
		ip = ip + ciphertext[int(c)+1]

	left_key  = ip[:34]
	right_key = '0b' + ip[34:70]
	
	for n in range(16):
		f = '0b'
		for c in e_bit_table:
			f = f + right_key[int(c)+1]
			
		right = xor(f, permuted_keys[15-n]) # this is K_n xor E(R_n-1)
		# use s-blocks
		s_output = s_block(s1, str(right[2:8]))
		s_output = s_output + s_block(s1, right[8:14])[2:]
		s_output = s_output + s_block(s1, right[14:20])[2:]
		s_output = s_output + s_block(s1, right[20:26])[2:]
		s_output = s_output + s_block(s1, right[26:32])[2:]
		s_output = s_output + s_block(s1, right[32:38])[2:]
		s_output = s_output + s_block(s1, right[38:44])[2:]
		s_output = s_output + s_block(s1, right[44:50])[2:]
		
		f = '0b'
		for i in p:
			f = f + s_output[int(i)+1]
		
		#print(s_output)
		#print(f)
		
		f = xor(f, left_key)
		
		left_key  = right_key
		right_key = f

	final_key = right_key[2:] + left_key[2:]
	for c in ip_inverse:
		plaintext = plaintext + final_key[int(c)-1]

	return plaintext
	
def encode(plaintext, permuted_keys):
	plaintext = format(plaintext, '#066b')
	ciphertext = ''
	ip = '0b'
	
	for c in init_permute:
		ip = ip + plaintext[int(c)+1]

	left_key  = ip[:34]
	right_key = '0b' + ip[34:70]
	
	for n in range(16):
		f = '0b'
		for c in e_bit_table:
			f = f + right_key[int(c)+1]
			
		right = xor(f, permuted_keys[n]) # this is K_n xor E(R_n-1)
		# use s-blocks
		s_output = s_block(s1, str(right[2:8]))
		s_output = s_output + s_block(s1, right[8:14])[2:]
		s_output = s_output + s_block(s1, right[14:20])[2:]
		s_output = s_output + s_block(s1, right[20:26])[2:]
		s_output = s_output + s_block(s1, right[26:32])[2:]
		s_output = s_output + s_block(s1, right[32:38])[2:]
		s_output = s_output + s_block(s1, right[38:44])[2:]
		s_output = s_output + s_block(s1, right[44:50])[2:]
		
		f = '0b'
		for i in p:
			f = f + s_output[int(i)+1]
		
		#print(s_output)
		#print(f)
		
		f = xor(f, left_key)
		
		left_key  = right_key
		right_key = f

	final_key = right_key[2:] + left_key[2:]
	for c in ip_inverse:
		ciphertext = ciphertext + final_key[int(c)-1]

	return ciphertext
	
def xor(string1, string2):
	str = '0b'
	
	# remove '0b' from start of binary strings
	string1 = string1[2:]
	string2 = string2[2:]
	
	for n in range(len(string1)):
		if string1[n] != string2[n]:
			str = str + '1'
		else:
			str = str + '0'
			
	return str
	
def s_block(s_n, bits):
	row = bits[0] + bits[5]
	col = bits[1:5]
	
	row = int(row, 2)
	col = int(col, 2)
	
	return format(s_n[row][col], '#06b')
	
# parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-e', '--encrypt', action='store_true', help='encrypt the text')
parser.add_argument('-d', '--decrypt', action='store_true', help='decrypt the text')
parser.add_argument('text', help='text to encrypt or decrypt')

args = parser.parse_args()

if args.encrypt and args.decrypt:
	print('Please specify either --encrypt or --decrypt')
elif not args.encrypt and not args.decrypt:
	str = input('Specify either encrypt/decrypt:\n')
	if str.lower() == 'encrypt':
		args.encrypt = True
	elif str.lower() == 'decrypt':
		args.decrypt = True
	else:
		print('Invalid Input')
		exit(1)

# generate subkeys
permute_keys = generate_subkeys()

# convert text to hex input
text = int('0x' + args.text, 16)


output = ''

if args.encrypt:
	print('Encrypting text: ' + args.text)
	output = encode(text, permute_keys)
	
	# convert binary output to hex string
	output = hex(int(output, 2))
	
	print('Encrypted ciphertext: ' + output[2:].upper())
	
if args.decrypt:
	print('Decrypting text: ' + args.text)
	output = decode(text, permute_keys)
	
	# convert binary output to hex string
	output = hex(int(output, 2))
	
	print('Decrypted plaintext: ' + output[2:].upper())

