#!/usr/bin/env python
# ******************************************************************************
# bruteForceDecrypt.py
#
# Uses a brute force algorithm to determine a secret key
# ******************************************************************************

import os

def int2hex(i):
	if i == 10:
		return 'a'
	elif i == 11:
		return 'b'
	elif i == 12:
		return 'c'
	elif i == 13:
		return 'd'
	elif i == 14:
		return 'e'
	elif i == 15:
		return 'f'
	else:
		return str(i)

# generate all permutations of a key
for i in range(16):
	for j in range(16):
		for k in range(16):
			print('0x' + int2hex(15-i) + int2hex(15-j) + int2hex(15-k) + 'xx76f30303030')
			for l in range(16):
				for m in range(16):
					cmd = 'DES.py -d 0xBA352F54FDC334975AD4681705CA5D7D --key 0x' + int2hex(15-i) + int2hex(15-j) + int2hex(15-k) + int2hex(15-l) + int2hex(15-m) + '76f30303030 > NULL 2>&1'
					#print(cmd)
					result = os.system(cmd)
					if result == 0:
						print(cmd)
					#if(result != 1):
					#	print('0x' + int2hex(i) + int2hex(j) + int2hex(k) + int2hex(l) + int2hex(m) + '76f30303030')
	