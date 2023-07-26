from Crypto.Util import number
from Crypto.Util.Padding import pad,unpad

def split_block(data:bytes, block_size:int):
	for i in range(0,len(data),block_size):
		yield data[i:i+block_size]

def convert_bytes_bin(data:bytes, bit_size:int)->list:# little endian 
	data = int.from_bytes(data,'little')
	return [(data//(1<<i))&1 for i in range(bit_size)]

def convert_bin_bytes(data:list, bit_size:int)->bytes:# little endian 
	data = sum(data[i]<<i for i in range(bit_size))
	return data.to_bytes(bit_size//8,'little')

class Server:
	def __init__(self,bits):
		self.q,self.r = 0,0
		self.W = []
		## pub_key
		self.H = []
		
		self.block_size = 32 ## in bits
		assert bits&7 == 0 , "Must diviable by 8"
		assert bits>self.block_size+1, "Must larger than block_size"
		self.bits_protocol = bits
	
	def generate(self):
		# tmp = self.bits_protocol//self.block_size
		tmp = 2
		while True:
			self.W = []
			for i in range(1,self.block_size+1):
				self.W.append(number.getRandomRange(sum(self.W)+1,1<<(i*tmp) ))	
			# print(self.W)
			if sum(self.W)>(1<<self.bits_protocol):continue
			self.q = number.getRandomRange(sum(self.W),1<<(self.bits_protocol))
			self.r = number.getRandomRange(1,self.q)
			if number.GCD(self.r,self.q)!=1:continue
			break
			
		for i in range(self.block_size):
			self.H.append((self.W[i]*self.r)%self.q)
		# print(self.W)
	
	def encrypt(self,message: bytes) -> bytes:
		if len(message)%(self.block_size>>3)!=0: message = pad(message,self.block_size>>3)
		cipher_bytes = b''
		for data in split_block(message,self.block_size>>3):
			tmp = convert_bytes_bin(data,self.block_size)
			tmp = sum((a*b) for a,b in zip(tmp,self.H))#%self.q
			# print((tmp.bit_length()+7)//8)
			cipher_bytes += tmp.to_bytes((self.bits_protocol>>3)+1,'little')
		return cipher_bytes
	
	def __repr__(self):
		return f"public key: {self.H}"
	
if __name__=='__main__':
	server = Server(128)
	server.generate()
	m = b'CTF{CENSORED}'
	c = server.encrypt(m)
	print(c)
	print(server)
	