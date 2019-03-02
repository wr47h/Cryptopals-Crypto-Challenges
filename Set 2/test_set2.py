import unittest
from set2 import *

class TestCode(unittest.TestCase):
	def test_chall1(self):
		self.assertEqual(pkcs_padding("YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04")

if __name__ == "__main__":
	unittest.main()