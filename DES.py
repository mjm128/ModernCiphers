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
import os

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
	
	def encryptCBC(self, plainText):
		cipherText = ""
		InitVector = os.urandom(8) #Get 8 random bytes
		des_encrypt = des.new(self.key, des.MODE_ECB)
		
		while len(plainText) % 8 != 0:
			plainText += '\x00' #add null padding
		
		plainTextBlock = ""
		for index in range(0, 8):
			#XOR IV with first block of Text (8 bytes) 
			plainTextBlock += chr(ord(InitVector[index]) ^ ord(plainText[index]))
			#Now store the IV to the first 8 bytes of the cipherText
			cipherText = str(InitVector)
		
		for index in range(0, len(plainText), 8):
			cipherBlock = des_encrypt.encrypt(plainTextBlock)
			cipherText += cipherBlock
			
			if index+8 < len(plainText):
				XOR = [None] * 8
				plainTextBlock = plainText[index+8:index+16]
				#Next Round: XOR cipherBlock with plaintextBlock
				for element in range(0, len(cipherBlock)):
					XOR[element] = chr(ord(cipherBlock[element]) ^ ord(plainTextBlock[element]))
				
				plainTextBlock = "".join(XOR)
		
		return cipherText
	
	def decryptCBC(self, cipherText):
		plainText = ""
		InitVector = cipherText[0:8] #Grab IV from cipherText
		cipherText = cipherText[8:] #Remove IV from cipherText
		
		des_decrypt = des.new(self.key, des.MODE_ECB)
		
		for index in range(0, len(cipherText), 8):
			plainTextBlock = des_decrypt.decrypt(cipherText[index:index+8])
			
			if index == 0:
				#Now take first block of IV and XOR with output of decryption
				XOR = [None] * 8
				for element in range(0, 8):
					XOR[element] = chr(ord(InitVector[element]) ^ ord(plainTextBlock[element]))
				plainText += "".join(XOR)
			
			elif index+8 <= len(cipherText):
				Block = [None] * 8
				#Next Round: XOR cipherBlock with plaintextBlock
				for element in range(0, len(cipherBlock)):
					Block[element] = chr(ord(cipherBlock[element]) ^ ord(plainTextBlock[element]))
				
				plainText += "".join(Block)
			
			cipherBlock = cipherText[index:index+8]
			
		return plainText