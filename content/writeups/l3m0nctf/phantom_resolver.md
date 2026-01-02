+++
date = '2026-01-02T09:20:02+05:30'
draft = false
title = 'Phantom Resolver'
+++

The challenge provides us with 2 binary files:
- server_daemon
- libmonitor.so

Looking at the server daemon decompilation: 

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char **v3; // rbx

  print_banner(argc, argv, envp);
  printf("\n[*] Starting daemon in ");
  if ( argc <= 1 )
  {
LABEL_7:
    puts("INTERACTIVE mode");
    puts("[!] Warning: daemon mode not enabled");
    puts("[!] Use --daemon flag for production deployment");
  }
  else
  {
    v3 = argv + 1;
    while ( strcmp(*v3, "--daemon") )
    {
      if ( ++v3 == &argv[(unsigned int)(argc - 2) + 2] )
        goto LABEL_7;
    }
    puts("DAEMON mode");
  }
  putchar(10);
  initialize_subsystems();
  puts("\n[*] Running system integrity check...");
  system_check();
  puts("\n[*] Daemon initialization complete");
  return 0;
}
``` 

We can see that it prints some lines and then calls `system_check()`, looking at system check: 

```
// attributes: thunk
__int64 system_check(void)
{
  return system_check();
}
```

the disassembly says:
```
jmp     cs:off_5018
``` 

So it jumps to some offset thats not part of this binary, this is where the `libmonitor.so` comes into play. Let's decompile the so file. 

Looking at the functions, we see a `system_check` function, We don't need to understand the entire function, but here's the important parts

```
if ( v2 >= 0
    && (close(v2), v3 = open("/proc/self/exe", 0), v4 = v3, v3 >= 0)
    && (lseek(v3, 12288, 0), v5 = read(v4, &buf, 6u), close(v4), v5 > 5)
    && buf == 1330792515
    && v8 == 16717
    && (unsigned int)sub_1300(v4) )
  {
    return (int (*)())backdoor_function;
  }
  else
  {
    return normal_function;
  }
```

Some specific condition triggers the `backdoor_function`, otherwise it just runs the `normal_function`. Convering these integer values into ASCII: 
```
buf == 1330792515 -> CHRO
    && v8 == 16717 -> MA
``` 
We get "CHROMA", This will come in handy later.

The `normal_function` doesn't really do much 

```
int normal_function()
{
  puts("[*] Monitoring system: nominal");
  return puts("[*] All security checks passed");
}
```

Let's move on to the backdoor function. We can see it using our hardoded key 

- `v3 = _mm_cvtsi32_si128(buf);` -> Just the integer buf_int
- `v4 = _mm_xor_si128(_mm_srli_epi32(v3, 0x10u), v3);`
- `v5 = _mm_cvtsi128_si32(_mm_xor_si128(v4, _mm_srli_epi32(v4, 8u))) ^ v10 ^ v11;` -> XOR the integer with itself right-shifted by 16 bits

This seems to calculate the key from "CHROMA".

- Take 0x4F524843 ("CHRO") and XOR it with itself right-shifted by 16 bits → 0x4F520711
- Take that result and XOR it with itself right-shifted by 8 bits → 0x4F1D5516
- Take the lowest byte (0x16) and XOR it with 'M' (0x4D) and 'A' (0x41)
- 0x16 ^ 0x4D ^ 0x41 = 0x1A (Decimal 26)

So the calculated key is `0x1A`

Now we apply this key (0x1A) to the hex strings found in backdoor_function.

```
  si128 = _mm_load_si128((const __m128i *)&xmmword_2120);
  v13[0] = _mm_load_si128((const __m128i *)&xmmword_2130);
  *(__m128i *)((char *)v13 + 9) = _mm_load_si128((const __m128i *)&xmmword_2140);
```

The logic is a "rolling XOR" where the key changes slightly using the previous byte
```
 v7 = 86;
 do
  {
    p_si128 = (__m128i *)((char *)p_si128 + 1);
    putchar((unsigned __int8)v5 ^ (unsigned __int8)v7);
    v7 = p_si128->m128i_i8[0];
  }
  while ( p_si128->m128i_i8[0] );
```

We can script the decryption logic in python, and retrieve the hardcoded bytes from the binary (xmmword_21...).

```
import struct

def solve():
    print("[-] Configuring Master Key...")
    # 1. The hardcoded key derived from "CHROMA"
    key = 0x1A  # Calculated from step 1
    
    # 2. Reconstruct the encrypted buffer (Little Endian)
    # xmmword_2120
    chunk1 = bytes.fromhex("772A6E742E726A615C4E59742A772956")[::-1]
    
    # xmmword_2130 (We only need the first 9 bytes before the overwrite hits)
    chunk2_full = bytes.fromhex("4579746F7C2B4568296C762A69296845")[::-1]
    chunk2_part = chunk2_full[:9] 
    
    # xmmword_2140 (This overwrites the buffer starting at offset 25)
    # Note: The snippet for 2140 was 30 chars long (15 bytes)
    chunk3 = bytes.fromhex("676368296E692E774579746F7C2B45")[::-1]
    
    # Combine them: Chunk1 + Chunk2_Part + Chunk3
    # (The overwrite logic in C effectively stitches these together)
    ciphertext = chunk1 + chunk2_part + chunk3
    
    print("[-] Decrypting...")
    
    flag = ""
    v7 = 86 # Initial seed (0x56)
    
    for byte in ciphertext:
        # Decrypt char: Key ^ Previous_Byte
        decrypted_char = key ^ v7
        flag += chr(decrypted_char)
        
        # Update Previous_Byte to current ciphertext byte
        v7 = byte
        
    print(f"\n[+] FLAG FOUND: {flag}")

if __name__ == "__main__":
    solve()
```

Running this script gives us the flag:

```
L3m0nCTF{ph4nt0m_r3s0lv3r_1func_m4st3ry}
```