#!/usr/bin/env python
# ******************************************************************************
# DES.py
#
# DES Encryption/Decryption Algorithm
# ******************************************************************************

import argparse

plaintext  = ''
ciphertext = ''

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

if args.encrypt:
	print('Encrypting text: ' + args.text)

if args.decrypt:
	print('Decrypting text: ' + args.text)
