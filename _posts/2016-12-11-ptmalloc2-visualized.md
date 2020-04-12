---
layout: post
title: Ptmalloc2 Visualized in GDB
---
## Intro
Many CTF contests these days have Pwn challenges that require the player to perform various heap exploitation techniques in order to solve the challenge.

However, in order to know which of these many exploitation techniques to use, one must first gain a clear understanding of how ptmalloc2 works. 

While there are already several fantastic blogs and articles that explain how ptmalloc2 works, I wanted to add supplementary material by walking through what allocating and freeing heap chunks looks like in GDB, in order to help both myself and others better visualize what the memory allocator actually does.

## Ptmalloc2
There are many different heap allocators that are used in the real world, each one using their own implementation.

For this specific post, we will be focusing on just Ptmalloc2. 

Ptmalloc2 is the default memory allocator used by glibc and is the one most often encountered in CTF challenges. 

## Allocating Memory

Allocating memory chunks is fairly straightforward in Ptmalloc2. 

When memory is requested dynamically, a pointer is returned by the memory allocator that points **not to the beginning of the heap chunk, but rather the beginning of buffer in the heap chunk.** In other words, the address that a call to `malloc()` returns points to the address **after** the `prev_size` and `size` headers. This distinction is important to remember. 

In addition, it is also important to remember that  

We can visualize this by writing a small program that allocates 4 heap chunks and running the program through `ltrace`. (Ignore the free part for now):

{% highlight C %}
/* 
    fastbin.c
    compiled with: gcc -o fastbin fastbin.c
*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(void){
    char *ptr1;
    char *ptr2;
    char *ptr3;
    char *ptr4;

    ptr1 = malloc(24);                // chunk 1
    strcpy(ptr1, "AAAAAAAAAAAAAAAA");
    ptr2 = malloc(24);                // chunk 2
    strcpy(ptr2, "BBBBBBBBBBBBBBBB");
    ptr3 = malloc(24);                // chunk 3
    strcpy(ptr3, "CCCCCCCCCCCCCCCC");
    ptr4 = malloc(24);                // chunk 4
    strcpy(ptr4, "DDDDDDDDDDDDDDDD");

    free(ptr3);
    free(ptr1);
    return 0;
}
{% endhighlight %}

{% highlight bash %}
$ ltrace ./fastbin
__libc_start_main(0x40057d, 1, 0x7ffe38e8aed8, 0x400670 <unfinished ...>
malloc(24)                                                             = 0x602010
malloc(24)                                                             = 0x602030
malloc(24)                                                             = 0x602050
malloc(24)                                                             = 0x602070
free(0x602050)                                                         = <void>
free(0x602010)                                                         = <void>
+++ exited (status 0) +++
{% endhighlight%}

We can also visualize these chunks, including their contents, in GDB.

If we set a breakpoint on the first `free()`, we see that the heap looks like the following before first `free()` is called.

{% highlight bash %}
gdb-peda$ x/32xg 0x602010-16
0x602000:       0x0000000000000000      0x0000000000000021
0x602010:       0x4141414141414141      0x4141414141414141
0x602020:       0x0000000000000000      0x0000000000000021
0x602030:       0x4242424242424242      0x4242424242424242
0x602040:       0x0000000000000000      0x0000000000000021
0x602050:       0x4343434343434343      0x4343434343434343
0x602060:       0x0000000000000000      0x0000000000000021
0x602070:       0x4444444444444444      0x4444444444444444
0x602080:       0x0000000000000000      0x0000000000020f81
0x602090:       0x0000000000000000      0x0000000000000000
0x6020a0:       0x0000000000000000      0x0000000000000000
0x6020b0:       0x0000000000000000      0x0000000000000000
0x6020c0:       0x0000000000000000      0x0000000000000000
0x6020d0:       0x0000000000000000      0x0000000000000000
0x6020e0:       0x0000000000000000      0x0000000000000000
0x6020f0:       0x0000000000000000      0x0000000000000000
{% endhighlight %}

Notice the `0x21` field in the metadata of each chunk refers to the chunk's `size` value which is `0x20`, the true size of the heap chunk, not the size we requested using `malloc()`, and the `prev_in_use` bit that is set to `0x1`, meaning the previous chunk is currently being used.

As a side note, the first chunk in the heap always has its `prev_in_use` bit set to `0x1` because there is never a previous chunk before it.

If for example, we had placed 20 letters instead of 16 letters into chunk 1, we would see that the extra data would be placed into chunk 2's `prev_size` field.  

{% highlight bash %}
0x602010:       0x4141414141414141      0x4141414141414141
0x602020:       0x0000000041414141      0x0000000000000021
{% endhighlight %}


If at a later time, chunk 1 is then `free()`'d, we would expect to see `0x0000000041414141` replaced with the actual `prev_size`. However, this isn't the case with fastbin chunks as we will talk about later.

Lastly, notice the `0x20f81` field which refers to how much space there is left on the heap available to be returned in subsequent memory allocations. This area after our last `malloc()`'d is the **wilderness chunk**

## Freeing Memory

## Bins
 
There are 4 types of bins used by Ptmalloc2. 


**1. fast bins**

**2. unsorted bins**

**3. small bins**

**4. large bins**


- Fastbins
asdf


