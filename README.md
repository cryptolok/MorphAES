# MorphAES
IDPS & SandBox & AntiVirus STEALTH KILLER.

![](https://i.imgur.com/JwbqV11.png)

MorphAES is the world's first polymorphic shellcode engine, with metamorphic properties and capability to bypass sandboxes, which makes it undetectable for an IDPS, it's cross-platform as well and library-independent.

Properties:
* Polymorphism (AES encryption)
* Metamorphism (logic and constants changing)
* Platform independent (Linux/BSD/Windows)
* IDPS stealthing (the total number of possible signatures is more the number of atoms in the universe for one given code)
* Sandbox evasion (special assembly instructions)
* Bad characters avoiding (\x00, \x04, \x05, \x09, \x0a, \x20)
* Can produce executables and be exploited remotely
* Input code can have arbitrary length
* Possibility for a NOP sled

Dependencies for the morpher:
* **Python 2.7** - main engine

Dependencies for the code execution:
* **64-bit Intel AES-NI** - for decryption

Nonetheless, there are some limitations (aka white-hat aspects):
* Metamorphism is not very robust and can be detected using regular expressions (but can be improved pretty easily)
* Unicode null bytes might still work (but who cares?)
* It will only work on 64-bit Intel processors with [AES-NI](http://ark.intel.com/search/advanced/?s=t&AESTech=true) support, but since all the user's PCs (like Pentium, Celeron, i3, i5, i7) and the industry's servers (like Xeon) have it, it's more a specification, rather than a limitation, thus a 32-bit implementation is unpractical
* Almost any shellcode is guarantee to work however, an arbitrary code doesn't (to avoid malware abuse)
* Windows/BSD PoC and executables are in progress, as well as the ARM version

## How it works

1. Shellcode padding with NOPs (since AES is a block cipher) and adding an optional NOP sled
2. Shellcode encryption with a random key using custom AES-128-ECB (not the best, but the simplest) - polymorphism
3. Constants randomization, logic changes, instructions modification and rewriting - metamorphism

### HowTo

You will have to assemble my custom AESNI-128-ECB implementation using an Intel x64 CPU and put it in the same folder with the python script.

For Linux:
```bash
sudo apt-get install python
as --64 AES.s -o AES.o
ld AES.o -o AES
```
Execute the Python script and enter your shellcode or nothing for a default Linux shell. You can specify your own execution address as well.

It is also possible to build and execute on Windows/BSD/Mac, but I'm still testing it.

You can test the Linux PoC in assembly:
```bash
as --64 shellcodePoC.s -o shellcodePoC.o
ld shellcodePoC.o -o shellcodePoC
./shellcodePoC
```
or in C:
```bash
gcc -m64 -fno-stack-protector -z execstack shellcode.c -o shellcode
./shellcode
```

Every file is commented and explained

#### Tests

At this point, it should be pretty obvious that, the hashes would be different every time, but let's compare SSDEEPes of 2 Linux executables of the same shellcode:
* 96:GztTHyKGQh3lo6Olv4W4zS/2WnDf74i4a4B7UEoB46keWJl09:Gzty6VOlvqSTDflmNroh,
* 96:GQtT23yKmFUh3lo6OlOnIrFS4rkoPPf74i4a4B7UEoB46keWJ5:GQtCGWVOlOWFSsPflmNroh,

Well, there's something in common, but globally those are 2 different signatures, now what about the shellcode it-self:
* 6:Cq8bnJYn4Xkm3qECaADATyEnT8snTiETiTCfhUaAP6mYGexCKdKZzX+rqVCKdKTc:xuJ0Zp2xRZof79G/KVyk/KTbA,
* 6:vrg+T1RfLEQD/zD1DZzDJ3zDBfjDcDRJDULUwzWq0Cgk3g4zE/Yq0Cgk3gy12Ots:vLjjEszWCp3w/YCp3Nts,

Almost totally different signatures for the same morphed shellcode!

At the publication date, the executable was detected as a shellcode only by 2 out of 53 antiviruses (AVG and Ikarus) on [virustotal](https://virustotal.com/en/file/05491801b765bb080bf0f20e5fc17e2b187a521a781dd0dbb47e19f1e6fc0a98/analysis/1468267426/), but now, it just fails to analyze.

[malwr](https://malwr.com/analysis/MTM4NDhkZmI2ZTZlNDNkMzkyZjRmZGY3ZWU0ZWEwMTQ/) and [cuckoo2](https://linux.huntingmalware.com/analysis/927/summary/) don't see anything suspicious.

On the reverser's perspective, IDA won't see anything either.

Radare2 would show the real instructions only if assembled by the assembler it-self however, it doesn't detects any crypto or suspicious activity for the executable.

Althrough, I didn't test it personally, I think that FortiSandbox, Sophos Sandstorm, Blue Coat, GateWatcher and their derivatives might fail badly...

##### To put it in the nutshell

Basically, it can transform a script-kid's code (or a [known-one](http://shell-storm.org/shellcode/)) into a zero-day.

IDPS will fail because, it's almost impossible to make a signature and difficult to make a regular expression or heuristic analysis.

Most of the sandboxes doesn't use Intel's AES-NI instructions directly, so they will not execute the code, so "everything is fine" for them, whereas it's not.

The only way to defeat this type of shellcode is to use an appropriate sandboxing or/and an AI.

Of course DEP/NX/CANARY/ASLR should work as well.

Notice that, the whole execution is done by a pure assembly, no Python (or OpenSSL) is needed for the shellcode's execution since, I use built-in assembly instructions only, thus it's system-independent (surely, you will have to assemble it for each-one by adapting the instructions/opcodes, but they are still same).


###### Notes

This is still a work in progress, I will implement Windows and BSD/Mac engines and PoCs ASAP.

IDPSes and sanboxes are the past.

> "Tradition becomes our security, and when the mind is secure it is in decay."

Jiddu Krishnamurti

