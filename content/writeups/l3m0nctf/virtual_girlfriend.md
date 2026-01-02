+++
date = '2026-01-02T10:09:21+05:30'
draft = false
title = 'Virtual girlfriend'
+++

We have been given a `main.s` file, written in AT&T syntax... (or as I like to call it, the wrong syntax). Our goal is to find out the return value of the program.

The main concept of this challenge is that it has some infinite loops and dead code that prevents you from executing it normally.

```
 label1:
    push rbp
    mov rbp, rsp
    call label2
    call label3
    jmp label4
    pop rbp
    ret
...
 label4:
    jmp label4 
```

- After calling label2 and label3, there is a jmp label4
- label4 calls `jmp label4`, creating an infinite loop. 
- The solution is to remove lavel4 completely.

Inside label3, 
```
mov r8, 0x12345678
cmp r8, 0x12345678
je label5
...
 label5:
    xorq %r8, %r8

label12:
    incq %r8
    cmpq $0, %r8
    jne label12
    jmp label5 
```
Label5 will xor r8 with itself, then increment it in label12, comparing it with 0, We then jump to label12 again causing another infinite loop by counting. 

Now instead of calculating the value in `rax` manually. It would be better to let the program do it for us. After fixing all the dead code and converting it into intel syntax using an LLM:

```
.intel_syntax noprefix   # <--- CRITICAL FIX: Tells 'as' to use Intel syntax
.section .text
    .global _start

_start:
    xor rax, rax
    mov rdi, 0xb0bacafe
    mov rsi, 0x1337
    call label1

    # Exit cleanly so we can verify the result in GDB
    mov rdi, rax
    mov rax, 60
    syscall

label1:
    push rbp
    mov rbp, rsp
    call label2
    call label3
    # jmp label4         # <--- REMOVED: Infinite Loop
    pop rbp
    ret

label3:
    push rbp
    mov rbp, rsp
    
    # Standardized to Intel Syntax (No '%' signs, correct operand order)
    mov rax, rdi
    xor eax, 0xcafebabe
    mov rbx, rsi
    shl rbx, 4
    add rax, rbx
    
    mov r8, 0x12345678
    cmp r8, 0x12345678
    # je label5          # <--- REMOVED: Jump to infinite loop
    
    mov rcx, rax
    and ecx, 0xff00ff00
    shr rcx, 8
    xor rax, rcx
    sub rax, 0x1234
    rol rax, 3
    
    pop rbp
    ret

label2:
    push rbx
    push rcx
    push rdx

    mov rcx, rdi
    xor rcx, rsi        
    mov rbx, 12           

label6:
    test rcx, 1
    jnz label8
label7:
    shr rcx, 1
    jmp label9
label8:
    lea rdx, [rcx + rcx*2]
    add rdx, 1
    mov rcx, rdx
label9:
    mov rdx, rcx
    and edx, 0xff
    xor rdx, 0x5a
    cmp rdx, 0x7f
    jae label10
    add rdx, 3
    jmp label6
label10:
    sub rdx, 1
label11:
    dec rbx
    jnz label6
    mov rax, -1          # Fixed: 0xffffffff in 64-bit is often cleaner as -1
    test rax, rax
    jz label60
    pop rdx
    pop rcx
    pop rbx
    ret

# --- Dead Code (Kept to satisfy labels, but unreachable) ---
label4:
    jmp label4
label5:
    xor r8, r8
label12:
    inc r8
    cmp r8, 0
    jne label12
    jmp label5
label60:
    mov r9, -1
label61:
    add r9, 2
    test r9, r9
    jns label61
    jmp label60
```

assemble using 
```
as exploit.s -o exploit.o
```
then link 
```
ld exploit.o -o exploit
```

Now we can debug the program in `gdb`

```
gdb ./exploit
```

Inside gdb, we can start the program, and break after label1, which will contain the correct value 

```
=> 0x401000 <_start>:   xor    rax,rax
   0x401003 <_start+3>: movabs rdi,0xb0bacafe
   0x40100d <_start+13>:        mov    rsi,0x1337
   0x401014 <_start+20>:        call   0x401025 <label1>
   0x401019 <_start+25>:        mov    rdi,rax <- break here
```

Now looking at the register `rax` gives us the final value that we need 

```
gef➤  info registers rax
rax            0x3d1fc86f8         0x3d1fc86f8
```