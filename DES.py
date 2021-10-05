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
	
	key48 = '0b'
	for n in range(16):
		combined_str = left_blocks[n][2:] + right_blocks[n][2:]
		for c in permute_key48:
			key48 = key48 + combined_str[int(c)-1]
		permuted_keys += [key48]
	
	return permuted_keys

def shift_key(left_key, right_key, shift):
	left_key  = '0b' + left_key[2+shift:30] + left_key[2:2+shift]
	right_key = '0b' + right_key[2+shift:30] + right_key[2:2+shift]
	
	return left_key, right_key
	
def encode(plaintext):
	plaintext = format(plaintext, '#066b')
	ciphertext = ''
	
	return ciphertext
	
def decode(ciphertext):
	ciphertext = format(ciphertext, '#066b')
	plaintext = ''
	ip = '0b'
	print(ciphertext)
	
	for c in init_permute:
		ip = ip + ciphertext[int(c)+1]

	left_key  = ip[:34]
	right_key = '0b' + ip[34:70]

	return plaintext

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

if args.encrypt:
	print('Encrypting text: ' + args.text)
	
if args.decrypt:
	print('Decrypting text: ' + args.text)
	decode(text)

