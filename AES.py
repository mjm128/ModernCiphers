try:
	from Crypto.Cipher import AES as aes
except ImportError as error:
	print("\nImport Error: Please install pyctrypto")
	if sys.version[0] == '2':
		version = ""
	if sys.version[0] == '3':
		version = "3"
	print("Example: sudo pip"+version+ " install pycrypto")
	quit()
import binascii

class AES():

	def setKey(self, key):
		if len(key) == 16:
			self.key = key
			return True
		print("Error: Key length must be 16 characters long")
		return False

	def encrypt(self, plainText):
		cipherText = ""
		aes_cipher = aes.new(self.key, aes.MODE_ECB)
		
		while len(plainText) % 16 != 0:
			plainText += '\x00' #add null padding
		
		for index in range(0, len(plainText), 16):
			cipherText += aes_cipher.encrypt(plainText[index:index+16])
		
		return cipherText

	def decrypt(self, cipherText):
		plainText = ""
		aes_cipher = aes.new(self.key, aes.MODE_ECB)
		
		for index in range(0, len(cipherText), 16):
			plainText += aes_cipher.decrypt(cipherText[index:index+16])
		
		return plainText