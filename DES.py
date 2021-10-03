#!/usr/bin/env python
# ******************************************************************************
# DES.py
#
# DES Encryption/Decryption Algorithm
# ******************************************************************************

import argparse

key = 0x133457799bbcdff1
permute_key = [ 57, 49, 41, 33, 25, 17,  9,
				 1, 58, 50, 42, 34, 26, 18,
				10,  2, 59, 51, 43, 35, 27,
				19, 11,  3, 60, 52, 44, 36,
				63, 55, 47, 39, 31, 23, 15,
				 7, 62, 54, 46, 38, 30, 22,
				14,  6, 61, 53, 45, 37, 29,
				21, 13,  5, 28, 20, 12,  4]
				
				
def permute_56bit():
	str = '0b'
	for c in permute_key:
		# generate 56 bit key
		str = str + key[int(c)+1]
	return str

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

# convert hex key into binary
key = format(key, '#066b')

if args.encrypt:
	print('Encrypting text: ' + args.text)
	
	# generate 16 subkeys 
	print('K   ' + str(key))
	key = permute_56bit()
	print('K+  ' + str(key))
	
	left_key  = key[:30]
	right_key = '0b' + key[30:66]
	print('C   ' + str(left_key))
	print('D   ' + str(right_key))
	
if args.decrypt:
	print('Decrypting text: ' + args.text)

