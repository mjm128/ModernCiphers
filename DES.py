try:
	from Crypto.Cipher import DES as des
except ImportError as error:
	print("\nImport Error: Please install pyctrypto")
	if sys.version[0] == '2':
		version = ""
	if sys.version[0] == '3':
		version = "3"
	print("Example: sudo pip"+version+ " install pycrypto")
	quit()
import binascii

class DES():

	def setKey(self, key):
		if len(key) == 16:
			try:
				self.key = str(binascii.unhexlify(key))
				return True
			except:
				print("Error: Non-hexadecimal digit found")
				return False
		print("Error: Key length must be 16 characters long")
		return False

	def encrypt(self, plainText):
		cipherText = ""
		des_encrypt = des.new(self.key, des.MODE_ECB)
		
		while len(plainText) % 8 != 0:
			plainText += '\x00' #add null padding
		
		for index in range(0, len(plainText), 8):
			cipherText += des_encrypt.encrypt(plainText[index:index+8])
		
		return cipherText

	def decrypt(self, cipherText):
		plainText = ""
		print(cipherText)
		des_decrypt = des.new(self.key, des.MODE_ECB)
		
		for index in range(0, len(cipherText), 8):
			plainText += des_decrypt.decrypt(cipherText[index:index+8])
		
		return plainText