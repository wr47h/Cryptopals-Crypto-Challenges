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
		self.assertEqual(repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	def test_chall6(self):
		self.assertEqual(break_multikey_xor(), "Terminator X: Bring the noise")

	def test_chall8(self):
		self.assertEqual(detect_aes_in_ecb(), "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")

if __name__ == "__main__":
	unittest.main()