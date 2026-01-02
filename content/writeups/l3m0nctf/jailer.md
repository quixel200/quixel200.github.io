+++
date = '2026-01-02T10:25:08+05:30'
draft = false
title = 'Jailer'
+++

Let's decompile the binary and see what it does 

```
   sub_1280(a1, a2, a3);
    if ( !(unsigned int)sub_13A0() )
      return system(a2[1]);
```

It seems to expect a command line argument, if provided it calls `sub_13A0()` to 'check' the input and calls `system` on our input. 


Now you can just run `cat flag.txt` and it will print the flag locally. But let's dig a bit deeper.


```
__int64 sub_13A0()
{
  int v0; // ebp
  int v1; // ebx
  v0 = sub_12E0();
  v1 = open("flag.txt", 0);
  if ( v1 < 0 )
  {
    v1 = open("/flag.txt", 0);
    if ( v1 < 0 )
      return 0xFFFFFFFFLL;
  }
  dup2(v1, v0);
  close(v1);
  return 0;
}
```
 This seems to open the flag, `v0` is calculated in `sub_12E0`. The file descriptor for the flag is in `v1` which then gets closed after a `dup2` call. dup2 is used to duplicate the file descriptor.

 Let's look at what it calculate 

 ```
 __int64 sub_12E0()
{
  int v0; // ecx
  unsigned int v1; // eax
  int v2; // edx
  __int64 v3; // rax
  char v5[10]; // [rsp+Eh] [rbp-1Ah] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-10h]
  v0 = 0;
  v6 = __readfsqword(0x28u);
  strcpy(v5, "J41lBr34k");
  v1 = 4919;
  do
  {
    v2 = __ROL4__(v1, 3);
    v3 = v0++;
    v1 = 31337 * (v2 ^ (unsigned __int8)v5[v3]);
  }
  while ( v0 != 9 );
  return v1 % 0x61 + 103;
}
```

Reversing this logic: 

- Starting value: 4919
- For each character in "J41lBr34k":
  - Rotate left by 3 bits
  - XOR with character
  - Multiply by 31337
- Final: result % 97 + 103

We can write a small python script to calculate the fd for us 

```
def rol4(value, shift):
    """Rotate left 32-bit value by shift bits"""
    value &= 0xFFFFFFFF  # Keep as 32-bit
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def calculate_fd():
    key = "J41lBr34k"
    v1 = 4919
    
    print(f"Starting value: {v1}")
    print(f"Key string: '{key}'")
    print("\nStep-by-step calculation:")
    print("-" * 60)
    
    for i, char in enumerate(key):
        # Rotate left by 3
        v2 = rol4(v1, 3)
        print(f"Step {i+1}: char='{char}' (ASCII {ord(char)})")
        print(f"  After ROL4(3): {v1} -> {v2}")
        
        # XOR with character
        xor_result = v2 ^ ord(char)
        print(f"  After XOR with {ord(char)}: {v2} ^ {ord(char)} = {xor_result}")
        
        # Multiply by 31337
        v1 = (31337 * xor_result) & 0xFFFFFFFF  # Keep as 32-bit
        print(f"  After multiply by 31337: {v1}")
        print()
    
    # Final calculation: v1 % 97 + 103
    fd = (v1 % 97) + 103
    
    print("=" * 60)
    print(f"Final hash value: {v1}")
    print(f"FD calculation: {v1} % 97 + 103 = {v1 % 97} + 103 = {fd}")
    print("=" * 60)
    
    return fd
```

We get the value 128. 

In linux, each process has a file descriptor table that can be accessed using `/proc/[pid]/fd`, in this case... we can do `/proc/self/fd/128`. This will point to the flag file. 

So running 
```
cat /proc/self/fd/128
```
or 
```
cat <&128
```
will print the flag.
