+++
date = '2025-10-28T08:57:16+05:30'
draft = false
title = 'Registers'
+++

When running a program the CPU needs fast access to memory to perform operations efficiently. The time it takes for the CPU to fetch instructions from RAM is a very costly operation which is why we have registers.

The x86 64 bit architecture contains 16 registers each holding 64 bits of data, similarly the older x86 32 bit architecture had 9 registers each holding 32 bits data.

The 32 bit general purpose registers are:

```
eax   ebx   ecx   edx 
```

In 64 bit:

```
rax   rbx   rcx   rdx
```

In addition to these, there are 8 new registers:

```
r8  r9  r10  r11  ....  r15
```

There are also 5 registers that have specific purposes and we'll discuss later. They are:

```
esi edi ebp eip esp
```

On 64 bit:

```
rsi rdi rbp rip rsp
```

**Some trivia:** The first 8 bit processor released by Intel used registers `a`,`b`,`c`..., once 16 bit processor came along they were named `ax`,`bx` for `a extended`,`b extended` and so on. Very creative names,I know.

On 32 bit, they were then named `eax` for... extended a extended...? I am as lost as you are. Don't even ask why 64 bit starts with a `r`.

# The special registers

- `rip` - Your instruction pointer, points to the current instruction being executed in your program.
- `rsi, rdi` - source index and destination index, mostly used for string operations. 
- `rbp, rsp` - base pointer and stack pointer to keep track of the stack.

# Partial Access 

You can access partial values of a register 

- `eax` - the lower 32 bits
- `ax` - the higher 16 bits of eax 
- `al` - lower 8 bits 
- `ah` - higher 8 bits

```
Bits:  63                                          32 31               16 15        8 7        0
       ┌──────────────────────────────────────────────┬──────────────────┬──────────┬──────────┐
       │                    RAX (64 bits)             │<-   EAX (32) ->  │<- AX(16) │          │
       │                                              │                  │          │          │
       └──────────────────────────────────────────────┴──────────────────┴──────────┴──────────┘
                                                                      ▲            ▲        ▲
                                                                      │            │        │
                                                                      │            │        └─ AL (8 bits)
                                                                      │            └────────── AH (8 bits)
                                                                      └─────────────────────── AX (16 bits)

```


# Calling convention

When a function is called, its arguments are passed using registers, on x86 the order is:

```
1st argument     RDI 
2nd argument     RSI
3rd argument     RDX
4th argument     RCX
5th argument     R8
6th argument     R9
```

**Note:** The order differs slightly for direct system calls. 
