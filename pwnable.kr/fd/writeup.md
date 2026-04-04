# Writeup: fd (pwnable.kr)

## Challenge Info
- **Target:** `fd` (File Descriptor)
- **Vulnerability:** Predictable File Descriptor, Standard Input hijack
- **Source Snippet:**
  ```c
  int fd = atoi(argv[1]) - 0x1234;
  len = read(fd, buf, 32);
  if(!strcmp("LETMEWIN\n", buf)){
      system("/bin/cat flag");
  }
  ```

## Analysis
The program calculates a file descriptor by subtracting `0x1234` (4660 in decimal) from the first command-line argument. It then attempts to read 32 bytes from that file descriptor.

In Linux, file descriptor `0` is `stdin`. If we can make `fd` equal to `0`, the `read()` call will wait for input from the terminal instead of a file.

### Exploitation
To get `fd = 0`:
`argv[1] - 0x1234 = 0`
`argv[1] = 0x1234 = 4660`

We pass `4660` as the first argument and then provide the string `LETMEWIN` followed by a newline to satisfy the `strcmp`.

### Payload
```bash
echo "LETMEWIN" | ./fd 4660
```

## Flag
``Mama! Now_I_understand_what_file_descriptors_are!``
