import base64
import binascii


def pkcs_padding(str, padding):
	diff_len = padding - len(str)%padding

	str = binascii.hexlify(bytearray(str, 'utf-8')).decode('utf-8')
	for i in range(diff_len):
		str += binascii.hexlify(bytes([diff_len])).decode('utf-8')

	return binascii.unhexlify(str)

if __name__ == "__main__":
	pass