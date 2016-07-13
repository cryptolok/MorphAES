# MorphAES

MorphAES is the world's first polymorphic shellcode engine, with metamorphic properties and capability to bypass sandboxes, which make it undetectable for an IDPS, it's cross-platform as well and library-independent.

Properties:
* Polymorphism (AES encryption)
* Metamorphism (logic and constants changing)
* Platform independent (Linux/BSD/Windows)
* IDPS stealthing (the total number of possible signatures is more the number of atoms in the universe for one given code)
* Sandbox evasion (special assembly instructions)
* Realism (no null bytes)
* Can produce executables (malwares)

Dependencies for the morpher:
* **Python 2.7** - main engine
* **Python Crypto 2.6** - for encryption
Dependencies for the code execution:
* **Intel AES-NI** - for decryption

Nonetheless, there are some limitations (aka white-hat aspects):
* Shellcode's maximum length is 240 bytes (I don't really want to destroy the whole industry (at least for now), but if you're good at assembly and crypto, it's technically possible to extend it)
* Execution might lead to unexpected results if you use 8-bit registers (I'm not pretty sure why and how)
* Metamorphism is not very robust and can be detected using regular expressions (but can be improved pretty easily)
* Unicode null bytes might still work (but who cares?)
* It will surely work on 64-bit Intel processors with [AES-NI](http://ark.intel.com/search/advanced/?s=t&AESTech=true) support, but since all the user's PCs (like Pentium, Celeron, i3, i5, i7) and the industry's servers (like Xeon) have it, it's more a specification, rather than a limitation
* Windows/BSD PoC and executables are in progress...

## How it works

1. Shellcode padding with NOPs (since AES is a block cipher)
2. Shellcode encryption with a random key using AES-128-ECB (not the best, but the simplest) - polymorphism
3. Constants randomization & logic changes - metamorphism

### HowTo

For Linux:
```bash
sudo apt-get install python python-crypto
```
Execute the Pyhton script and enter your shellcode or nothing for a default Linux shell.

It is possible to build and execute on Windows/BSD/Mac as well, but I'm still testing it.

You can also use the Linux PoC in assembly:
```bash
as shellcode.s -o shellcode.o
ld shellcode.o -o shellcode
./shellcode
```
Every file is commented and explained

#### Tests

At this point, it should be pretty obvious that, the hashes would be different every time, but let's compare SSDEEPes of 2 Linux executables of the same shellcode:
* 96:GztTHyKGQh3lo6Olv4W4zS/2WnDf74i4a4B7UEoB46keWJl09:Gzty6VOlvqSTDflmNroh,
* 96:GQtT23yKmFUh3lo6OlOnIrFS4rkoPPf74i4a4B7UEoB46keWJ5:GQtCGWVOlOWFSsPflmNroh,

Well, there's something in common, but globally those are 2 different signatures, now what about the shellcode it-self:
* 48:eip2bR2LRNtRPORDGRopRBXR3cRzER2vRU9BnH6ksr:Srn+,
* 48:6RjNeR2IRN7RPWRDeRokRB5R3xRz3R28RUxFT2+75eFK9iKMAdXAJKo:O9Tdwoo,

Almost totally different signatures for the same morphed shellcode!

At the publication moment, the executable was detected as a shellcode only by 2 out of 53 antiviruses (AVG and Ikarus) on [virustotal](https://virustotal.com/en/file/05491801b765bb080bf0f20e5fc17e2b187a521a781dd0dbb47e19f1e6fc0a98/analysis/1468267426/).
[malwres](https://malwr.com/analysis/MTM4NDhkZmI2ZTZlNDNkMzkyZjRmZGY3ZWU0ZWEwMTQ/) with cuckoo2 doesn't see anything suspicious.

On the reverser's perspective, IDA won't see anything neither.
Radare2 would show the real instructions only if assembled by the assembler it-self however, it doesn't detects any crypto or suspicious activity for the executable.

Althrough, I didn't test it personally, I think that FortiSandbox, Sophos Sandstorm, Blue Coat, GateWatcher and their derivatives might fail badly...

##### To put it in the nutshell

Basically, it can transform a script-kid's code (or a [known-one](http://shell-storm.org/shellcode/)) into a zero-day.

IDPS will fail because, it's almost impossible to make a signature and difficult to make a regular expression or heuristic analysis.

Most of the sandboxes doesn't use Intel's AES-NI instructions directly, so they will not execute the code, so "everything is fine" for them, whereas it's not.

The only way to defeat this type of shellcode/malware is to use an appropriate sandboxing or/and an AI.

Notice that, the whole execution is done by a pure assembly, no Python (or shitty OpenSSL) in needed for the shellcode's/malware's execution since, I use built-in assembly instructions only, thus it's system-independent (surely, you will have to assemble it for each-one by adapting the instructions/opcodes, but they are still same).


###### Notes

This is still a work in progress, I will implement Windows and BSD/Mac engines and PoCs ASAP.
IDPSes and sanboxes suck.

> "Tradition becomes our security, and when the mind is secure it is in decay."

Jiddu Krishnamurti

