import unittest
from set1 import *

class TestCode(unittest.TestCase):
	def test_chall1(self):
		self.assertEqual(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	def test_chall2(self):
		self.assertEqual(xor_hex_strings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"), "746865206b696420646f6e277420706c6179")

	def test_chall3(self):
		self.assertEqual(single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), "Cooking MC's like a pound of bacon")

	def test_chall4(self):
		self.assertEqual(find_correct_string(), "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f") and self.assertEqual(single_byte_xor(find_correct_string()), "Now that the party is jumping")

	def test_chall5(self):
		self.assertEqual(repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

if __name__ == "__main__":
	unittest.main()