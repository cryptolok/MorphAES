#$ as AES.s -o AES.o
#$ ld AES.o -o AES

# has to be in one folder with the python script
# just a custom implementation of AESNI-128-ECB in x64 assembly, see shellcode.txt and shellcodePoC.s for more details
# it takes a key concatenated with the text to encrypt and outputs the ciphertext
# DISCLAIMER! this implementation has been purposely weakened in order to avoid bad characters for shellcode

.data
	.comm buffer, 16, 16

.globl _start
_start:
# key scheduling
callq  read
movaps %xmm0,%xmm5
pxor   %xmm2,%xmm2
aeskeygenassist $1,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm6
# no 4 block
aeskeygenassist $2,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm7
aeskeygenassist $8,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm9
aeskeygenassist $16,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm10
# no 32 block
aeskeygenassist $64,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm12
aeskeygenassist $128,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm13
aeskeygenassist $27,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm14
aeskeygenassist $54,%xmm0,%xmm1
callq scheduling
movaps %xmm0,%xmm15

read:
# reads 16 bytes from input
mov    $0x0,%rax
mov    $0x0,%rdi
mov    $buffer,%rsi
mov    $16,%rdx
syscall 
movaps buffer,%xmm0
retq   

write:
# write 16 bytes to output
movaps %xmm0,buffer
mov    $0x1,%rax
mov    $0x1,%rdi
mov    $buffer,%rsi
mov    $16,%rdx
syscall 
retq   

exit:
mov    $0x3c,%rax
mov    $0x0,%rdi
syscall 

scheduling:
pshufd $0b11111111,%xmm1,%xmm1
shufps $0b00010000,%xmm0,%xmm2
pxor   %xmm2,%xmm0
shufps $0b10001100,%xmm0,%xmm2
pxor   %xmm2,%xmm0
pxor   %xmm1,%xmm0
retq   

crypt:
callq read
cmp $16,%rax
jl exit
pxor %xmm5,%xmm0
aesenc %xmm6,%xmm0
aesenc %xmm7,%xmm0
aesenc %xmm9,%xmm0
aesenc %xmm10,%xmm0
aesenc %xmm12,%xmm0
aesenc %xmm13,%xmm0
aesenc %xmm14,%xmm0
aesenclast %xmm15,%xmm0
callq write
jmp crypt
