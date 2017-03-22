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
		if len(key) == 32:
			try:
				self.key = str(binascii.unhexlify(key))
				return True
			except:
				print("Error: Non-hexadecimal digit found")
				return False
		print("Error: Key length = "+str(len(key))+", Key length must be 32 hex characters long")
		return False
	
	def setIV(self, isEncryption):
		blockBytes = 16
		IVchoice = None
		while IVchoice != 'y' and IVchoice != 'n':
			IVchoice = raw_input("Do you want to enter your own Initialization Vector (Y/N): ").lower()
		if IVchoice == 'y':
			validIV = False
			while not validIV:
				self.IV = raw_input("Enter IV as "+str(blockBytes*2)+" hex characters: ").replace(" ", "")
				while len(self.IV) != blockBytes*2:
					self.IV = raw_input("Length of IV must be "+str(blockBytes*2)+", try again: ").replace(" ", "")
				try:
					self.IV = binascii.unhexlify(self.IV)
					validIV = True
				except:
					print("Invalid IV: Non-hex character detected")
			return True
		else:
			if isEncryption:
				self.IV = os.urandom(blockBytes) #Get 16 random bytes
				print("Randomly Generated IV: " + binascii.hexlify(self.IV))
			return False

	def encrypt(self, plainText):
		cipherText = ""
		aes_cipher = aes.new(self.key, aes.MODE_ECB)
		
		#Padding in format of: '\x03 \x03 \x03
		padNum = 16 - len(plainText) % 16
		while len(plainText) % 16 != 0:
			plainText += chr(padNum) #Add padding character
		
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
		padChar = plainText[-1]
		isPadding = False
		if padNum > 0 and padNum < 16:
			if padNum == 1 and plainText[-2] != padChar:
				#If only one padding character
				return plainText[:len(plainText)-1]
			isPadding = True
			for index in range(2, padNum):
				if plainText[-index] != padChar:
					isPadding = False
		if isPadding:
			return plainText[:len(plainText)-padNum]
		return plainText