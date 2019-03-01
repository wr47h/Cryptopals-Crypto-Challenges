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

def single_byte_xor_key(input_str):
	encoded = input_str
	scores = []
	for i in range(256):
		decoded = []
		for j in range(len(encoded)):
			decoded.append(encoded[j]^i)

		english_score = get_english_score(decoded)
		decoded = bytearray(decoded)

		scores.append((decoded, english_score, i))

	best_message = sorted(scores, key=lambda x: x[1], reverse=True)[0]
	return best_message[2]

def find_correct_string():
	list_strings = []
	final_list = []
	with open("chal4.txt", "r") as f:
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

def repeating_key_xor(input, key):
	if isinstance(input, str):
		msg = bytearray(input, 'utf-8')
	else:
		msg = input

	decoded = []
	KEYLEN = len(key)
	for i in range(len(msg)):
		decoded.append(msg[i]^ord(key[i%KEYLEN]))

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
		distance += count_set_bits(str1[i]^str2[i])
	return distance

def break_multikey_xor():
	with open('chal6.txt', 'r') as f:
		str = f.read().replace('\n', '')
	
	str = bytearray(str, 'utf-8')
	str = base64.b64decode(str)
	
	min_dist = 1000000000000
	min_key_size = 2
	decoded_list = []
	keysizes = []
	for KEYSIZE in range(2, 41):
		str1 = str[0:KEYSIZE]
		str2 = str[KEYSIZE:2*KEYSIZE]
		str3 = str[2*KEYSIZE:3*KEYSIZE]
		str4 = str[3*KEYSIZE:4*KEYSIZE]
		edist1 = edit_distance(str1, str2)
		edist2 = edit_distance(str3, str4)
		edist = (edist1+edist2)/2
		edist = edist/KEYSIZE
		
		keysizes.append((edist, KEYSIZE))

	keys_list = sorted(keysizes, key=lambda x: x[0], reverse=False)[:10]

	for _, min_key_size in keys_list:
		final_len = len(str)//min_key_size * min_key_size

		blocks_list = []
		ini = 0
		for i in range(0, final_len, min_key_size):
			blocks_list.append(str[ini:ini+min_key_size])
			ini += min_key_size

		charwise_list = []
		for i in range(min_key_size):
			charwise_list.append([])

		for i in range(len(blocks_list)):
			for j in range(len(charwise_list)):
				charwise_list[j].append(blocks_list[i][j])

		KEY = []
		for i in range(len(charwise_list)):
			KEY.append(single_byte_xor_key(charwise_list[i]))

		FINAL_KEY = ""
		for i in KEY:
			FINAL_KEY += chr(i)

		decoded = repeating_key_xor(str, FINAL_KEY)

		s = bytearray.fromhex(decoded)
		decoded_list.append((s.decode(), get_english_score(s), FINAL_KEY))

	final_string = sorted(decoded_list, key=lambda x: x[1], reverse=True)[0]
	# print("KEY: {}\nTEXT: {}".format(final_string[2], final_string[0]))
	return final_string[2]

if __name__ == "__main__":
	break_multikey_xor()