import itertools
import binascii


def XOR(message=None):
	xorKey = '01101001'
	message = 'dfjsdfjkdfnjkneffjvnjkndfjknnkjnjfkdjkn'
	message ='54575b4355565a5a54575f5a5a5e5557565b475e5b5b5e55565b5a5e5f5b5a5f5a575a545b5b5e'
	encrypted = ''
	for m, k in itertools.izip(message, itertools.cycle(xorKey)):
		encrypted += chr(ord(m) ^ ord(k))
	print encrypted
	print binascii.hexlify(encrypted)

XOR()