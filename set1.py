import base64
import binascii

def hex_to_base64(msg):
	msg = bytearray.fromhex(msg)
	encoded = base64.b64encode(msg)
	return encoded.decode('utf-8')

def xor_hex_strings(str1, str2):
	str1 = bytearray.fromhex(str1)
	str2 = bytearray.fromhex(str2)

	decoded = []

	for i in range(len(str1)):
		decoded.append(str1[i]^str2[i])

	decoded = bytearray(decoded)
	return binascii.hexlify(decoded).decode('utf-8')

def get_english_score(input):
	character_frequencies = {
		'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
	}

	return sum([character_frequencies.get(chr(i).lower(), 0) for i in input])

def single_byte_xor(input_str):
	encoded = bytearray.fromhex(input_str)
	scores = []
	for i in range(256):
		decoded = []
		for j in range(len(encoded)):
			decoded.append(encoded[j]^i)

		english_score = get_english_score(decoded)
		decoded = bytearray(decoded)

		scores.append((decoded, english_score))

	best_message = sorted(scores, key=lambda x: x[1], reverse=True)[0]
	return best_message[0].decode('utf-8')

def find_correct_string():
	list_strings = []
	final_list = []
	with open("file.txt", "r") as f:
		for l in f:
			l = l.strip()
			try:
				list_strings.append((l, single_byte_xor(l)))
			except:
				pass

	for orig, msg in list_strings:
		msg = bytearray(msg, 'utf-8')
		final_list.append((orig, get_english_score(msg)))

	best_message = sorted(final_list, key=lambda x: x[1], reverse=True)[0]
	return best_message[0]

def repeating_key_xor(input):
	msg = bytearray(input, 'utf-8')
	key = "ICE"

	decoded = []
	for i in range(len(msg)):
		decoded.append(msg[i]^ord(key[i%3]))

	decoded = bytearray(decoded)
	return binascii.hexlify(decoded).decode('utf-8')

def count_set_bits(n):
	count = 0
	while n:
		count += n&1
		n = n>>1

	return count

def edit_distance(str1, str2):
	distance = 0
	for i in range(len(str1)):
		distance += count_set_bits(ord(str1[i])^ord(str2[i]))
	return distance

if __name__ == "__main__":
	print(edit_distance("this is a test", "wokka wokka!!!"))