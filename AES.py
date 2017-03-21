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
		print("Error: Key length = "+str(len(key))+", Key length must be 16 ascii characters long")
		return False

	def encrypt(self, plainText):
		cipherText = ""
		aes_cipher = aes.new(self.key, aes.MODE_ECB)
		
		#Padding in format of: '\x00 \x00 \x03
		paddingCounter = 0
		while len(plainText) % 16 != 0:
			paddingCounter += 1
			if len(plainText) % 16 == 15:
				plainText += chr(paddingCounter)
			else:
				plainText += '\x00' #add null padding
		
		for index in range(0, len(plainText), 16):
			cipherText += aes_cipher.encrypt(plainText[index:index+16])
		
		return cipherText

	def decrypt(self, cipherText):
		plainText = ""
		aes_cipher = aes.new(self.key, aes.MODE_ECB)
		
		for index in range(0, len(cipherText), 16):
			plainText += aes_cipher.decrypt(cipherText[index:index+16])
		
		return self.removePadding(plainText)
	
	def encryptCBC(self, plainText):
		pass
	
	def decryptCBC(self, cipherText):
		pass
	
	def encryptCFB(self, plainText):
		pass
	
	def decryptCFB(self, cipherText):
		pass
	
	def removePadding(self, plainText):
		padNum = ord(plainText[-1])
		isPadding = False
		if padNum > 0 and padNum < 16:
			if padNum == 1 and plainText[-2] != '\x00':
				#If only one padding character
				return plainText[:len(plainText)-1]
			isPadding = True
			for index in range(2, padNum):
				if plainText[-index] != '\x00':
					isPadding = False
		if isPadding:
			return plainText[:len(plainText)-padNum]
		return plainText