+++
date = '2026-05-28T17:38:32+05:30'
draft = false
title = 'Writing Assembly'
+++

Your CPU does not understand code the way you think it does, Instructions to the CPU are specified in something called the Assembly languange, and this assembly differs based on the architecture of the CPU. Most of the systems run on the x86 Architecture which was developed by Intel back when I was not even born. There's also the different architecture that's prominenet when it comes to mobile devices(and even some laptops, such as the M series of chips on a Mac) known as ARM.

We will focus on x86 in this article.

# Your first program

If you haven't already, read up on [Registers](registers)

We'll write a simple program, that just exits with the status code 1337. In order to call `exit`, our program needs to interact with the Operating system.
This is done through the wonderful world of `syscalls`. When you invoke a syscall, the program hands over control to the operating system...which then performs whatever needs doing and then returns control back to the program. It is also worth nothing that most libc standard functions(You can ignore this if you don't know what libc is) are just wrappers that call syscalls.

Here's the definition of the `exit` function:
```
void exit(int status);
```

So we need to pass it a `status` as the first argument, which we can do through the `rdi` register. (Recall calling conventions from [Registers](registers)).

You can move data to registers using the `mov` instruction. 

```
mov rdi,1337
```

Here, we are moving the value 1337 into the register rdi. Neat.

In order to invoke a syscall, we need to place a syscall number into the rax register, and then use the `syscall` instruction. The syscall number for `exit` is 60.

```
mov rax,60
syscall
```

Perfect!... But wait, how do we assemble it?

First, let's create the `do.s` file.

```nasm
.intel_syntax noprefix
.global _start 

_start:
    mov rdi,1337
    mov rax,60
    syscall
```


- The `.intel_syntax noprefix` line tells the assembler to use the intel syntax(as opposed to AT&T, which looks horrible)
- `.global _start` tells the compiler to add `_start` to the object code so that when it is run, it starts here.

We can now make our assembly code into a program by using `gcc`:

```
gcc -nostdlib -o do do.s
```

The `-nostdlib` flag tells the compiler to not include the C standard library, which we don't need. This will also error out as the compiler will try to look for a `main` function.

Running the executable:

```
[quixel@quine quix]$ strace ./do
execve("./do", ["./do"], 0x7ffc45598450 /* 69 vars */) = 0
brk(NULL)                               = 0x563eae7a4000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f903aea2000
arch_prctl(ARCH_SET_FS, 0x7f903aea2b80) = 0
set_tid_address(0x7f903aea31a8)         = 16285
set_robust_list(0x7f903aea2e60, 24)     = 0
rseq({cpu_id_start=0, cpu_id=RSEQ_CPU_ID_UNINITIALIZED, rseq_cs=NULL, flags=0, node_id=0, mm_cid=0, slice_ctrl={request=0, granted=0, __reserved=0}, __reserved=0}, 33, 0, 0x53053053) = 0
mprotect(0x563ea83d7000, 4096, PROT_READ) = 0
mprotect(0x7f903aeea000, 8192, PROT_READ) = 0
exit(1337)
```

You have successfully written your first program in assembly! There are various other syscalls that you can explore, here's a great reference:


[https://syscall.sh/](https://syscall.sh/)
