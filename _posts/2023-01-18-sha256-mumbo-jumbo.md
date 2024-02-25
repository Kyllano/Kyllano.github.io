---
title: sha256 mumbo jumbo
date: 2023-02-28 20:06 +0100
author: Kyllano
categories: [Cryptography]
math: true
tags: [sha256,c,cryptography,cybersecurity]
---

<script src="https://polyfill.io/v3/polyfill.min.js?features=es6"></script>
<script type="text/javascript" id="MathJax-script" async
  src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js">
</script>


# Let's build some sha256 !

Hey everyone! Today, we'll take a look at how sha256 works under the hood. I'm making this post because I see a lot of people not talking about what sh256 does and how it is used, but not how it works and the mechanisms it uses. Furthermore, I see even less people actually implementing it by themselves from scratch. So join me today on this challenge where we try to build the sha256 algorithm from scratch in C and maybe inject it in Python (in a later post though). You might be wondering why we are doing this in C : C can handle very low level operation (which we are going to need) and is very fast. Rust also has those attributes, but C has the added bonus that the OG Python interpreter is written in C (look up [CPython](https://fr.wikipedia.org/wiki/CPython)) which means if we have enough energy (I don't right now), it is possible to directly plug our library into Python (using [C Python extension modules](https://docs.python.org/3/extending/extending.html)).

To build our sha256 library, I will go through each step of what sha is doing, then I'll explain what to do in said step and code it in C. I will try to be as explicit as possible to make this beginner friendly but some basic C syntax knowledge is required as well as some math (though I will try to be very xplicit and explain everything I can since I do not have a math background)

I am not going to go in detail about what has been said countless time before so here is [a video](https://youtu.be/S9JGmA5_unY) by 3Blue1Brown (check out his channel if you're into mathy stuff. He explain concepts very well and does not try to gatekeep math) explaining the capibilities and the basics of sha256.

Limitation of our final product :
* We will be building digests from strings. This is because it makes the process easier and sha256 is usually used to store password safely. But we won't be able to get sha from a file (though it is possible, but it require extra works and this gets out of the scope of simply building sha256 to understand how it works under the hood)

Another piece of information I should highlight, is that I am not going to focus on the *why* we do things, but more on the *how* said things are created. What I mean by that is that I will probably not explain the motivation of certain steps, or why sha256 was created the way it is. But I am going to write the sha and explain how I wrote it.

# Preprocessing

## From String to Message Schedule

### String to message block

First off, in this post, we are going to try and convert a string into a sha256. Our string will be `sha256 rocks!`. Let's convert this to bytecode using an [ASCII table](https://www.ascii-code.com/) (we could use a UTF-8, UTF-16 or UTF-32 table, but it would just make our message longer and increase the lookup time. For these operation, it is a good rule of thumb to just stick to ASCII).

But, I am very lazy. So for the sake of this tutorial (and as a warmup), let's make a simple C function to print our string in hexadecimal (We know that each `char` of our string is stored in 2*4 bits so we print it with `%#2x`) :
``` c
void print_hex_string(char* str){
    int i=0;
    while (str[i] != '\0'){
        printf("%#02x ", str[i]);
        i++;
    }
}
```

We then get this hexadecimal code for our string : `0x73 0x68 0x61 0x32 0x35 0x36 0x20 0x72 0x6f 0x63 0x6b 0x73 0x21`

Which in binary is 
```
01110011 01101000 01100001 00110010 //0x73(s) 0x68(h) 0x61(a) 0x32(2)
00110101 00110110 00100000 01110010 //0x35(5) 0x36(6) 0x20( ) 0x72(r)
01101111 01100011 01101011 01110011 //0x6f(o) 0x63(c) 0x6b(k) 0x73(s)
00100001                            //0x21(!) 
```

Alright we have our string in bytecode. But in order for our string to be used by the algorithm, the lenght of our message block (the message block is the data we will feed into the hashing algorithm) must be a multiple of 512 bits. We also have to append a single 1 to our string. Every bit that wasn't initialized will be set to zero. Which will give us the following :
```
01110011 01101000 01100001 00110010 //0x73(s) 0x68(h) 0x61(a) 0x32(2)
00110101 00110110 00100000 01110010 //0x35(5) 0x36(6) 0x20( ) 0x72(r)
01101111 01100011 01101011 01110011 //0x6f(o) 0x63(c) 0x6b(k) 0x73(s)
00100001 10000000                   //0x21(!) 0x80(the single 1 to append)
```

Moreover, the last 64 bits of our message block needs to be allocated (and will represent the lenght in bit of our bytecode). To do this, we have the following code :

```c
unsigned char* str_to_message_block(unsigned char* str, u_int64_t* lenght){
    u_int64_t string_lenght = 0;
    while (str[string_lenght] != '\0') string_lenght ++; //We compute the lenght of our string
    string_lenght *= 8; //Each char is 8 bits
    u_int64_t full_lenght = string_lenght + 64; //The 64 bit long number to indicate the lenght of our string
    u_int64_t number_of_0_to_pad = 512 - (full_lenght % 512);
    //We allocate the message block space
    unsigned char* message_block = (unsigned char*) malloc (sizeof(unsigned char) * ((full_lenght+number_of_0_to_pad)/8));
    //We rewrite the string char by char
    for (u_int64_t i=0; i < (string_lenght)/8; i++) message_block[i] = str[i];
    message_block[string_lenght/8] = 0b10000000; //We append the 1 to the string
    //Then we pad all the 0s needed
    for (u_int64_t i=(string_lenght)/8; i < (string_lenght + number_of_0_to_pad)/8; i++) message_block[i] = 0x00;
    //Finally, we put the 64 bit number at the end
    for (int i = 0; i < 8; i++){
        //very hacky, we copy byte by byte the lenght of the string (by shifting the bits to the right and each time only keeping the byte that we need)
        //This is because we need the 64 bit integer to be written in big endian format (don't ask me why \_°-°_/)
        message_block[((string_lenght+number_of_0_to_pad)/8) + i] = (string_lenght >> ((7*8) - (i*8))) & 0xff; }
    //We return the lenght
    *lenght = full_lenght + number_of_0_to_pad; 
    return message_block;
}
```

As said in the comments :
* Line 1 through 6 initialize the following variable : string_lenght (the lenght of the string), full_lenght (lenght of the string and the space needed to write the lenght of the string which is contained in a 64 bit integer), number_of_0_to_pad (the number of zeros needed for the whole message block to be a multiple of 512). All these lenghts counts a number on bit.
* Line 8 allocate an array of unsigned char which will contain the message block.
* Line 10 through 21 write the values of the string, the 64 bit lenght of the string and the 0s into previously allocated array. We also append a 1 to the string here.

So after calling that function, we get the following message block

```
01110011 01101000 01100001 00110010 //0x73(s) 0x68(h) 0x61(a) 0x32(2)
00110101 00110110 00100000 01110010 //0x35(5) 0x36(6) 0x20( ) 0x72(r)
01101111 01100011 01101011 01110011 //0x6f(o) 0x63(c) 0x6b(k) 0x73(s)
00100001 10000000 00000000 00000000 //0x21(!) 0x80(single 1) (zeros)
00000000 00000000 00000000 00000000 //zeros
...                                 //tons of zeros
00000000 00000000 00000000 01101000 //0x00000068(lenght of the string = 104)
```

### From Message block to Message Schedule

Now that we have our message block, we can convert it to a message schedule. A message schedule is nothing but one block padded with enough zeros to make an array of 32 bit integer with a lenght of 64.

Thus, since each block is 512 bit (or 16 integer of 32 bits), we only have to copy a block, then pad it with 48 32-bit integer set to 0 (which is 192 bytes), then repeat for each block. This gives the subsequent code :

```c
u_int32_t* create_message_schedule(unsigned char* message_block, u_int32_t* lenght_message_schedule, u_int64_t lenght_message_block){
    //We give it a size in byte, transform it ot a size in bit, then check the number of block present
    u_int32_t nbBlocs = (lenght_message_block*8) / 512;

    //We allocate the message schedule array and set its lenght
    u_int32_t* message_schedule = (u_int32_t*) malloc(sizeof(u_int32_t) * 64 * nbBlocs);
    *lenght_message_schedule = 64*nbBlocs;

    //Copy the first block, then pad it with 192 bytes of 0s. Rince and repeat for each blocks.
    for (u_int32_t bloc_i = 0; bloc_i < nbBlocs; bloc_i++){
        //memcpy et memset prennent des longueurs en byte
        memcpy(&message_schedule[64*bloc_i], &message_block[64*bloc_i], 64);
        memset(&(message_schedule[bloc_i*64+16]), 0x00, 192);
    }

    return message_schedule;
}
```
We're almost set, we just need to check if our endianness is going to be a problem

### Endianness is problematic

Now we have a message schedule that is in big endian. That is great, but our operations on integer will suffer from this if our machine is in little endian (overflowing additions andbit shifting operations will certainly not work in the same way.). To dodge this problem, we have to convert the message schedule to little endian if our machine is little enian.

First let's check if our machine is little endian with this bit of code stolen from [stackoverflow](https://stackoverflow.com/questions/4181951/how-to-check-whether-a-system-is-big-endian-or-little-endian) and explained [here](https://stackoverflow.com/questions/12791864/c-program-to-check-little-vs-big-endian/12792301#12792301) :

```c
int isLittleEndian = 1;
if (*((char *)&isLittleEndian) == 1) change_message_schedule_endian(message_schedule, lenght_message_schedule);
```

Now let us create that `change_message_schedule_endian(message_schedule, lenght_message_schedule)` function. To do this, we first need a function that can change the endianness of a 32-bit integer.

<img src="/assets/img/sha256/endianness_had.png" alt="endianness" style="float: left" width="600"/>

As we can see from the next image above, we only have to get each byte of the number and swap the 1st and 4th, as well as swapping the 2nd and 3rd byte. To get each byte and place them in the good position, we simply make an AND operation on the location of the byte, and shift it to its required position. Then, it is only a matter of an OR operation on each bytes. This gives us the ensuing code :

```c
u_int32_t endian_converter(u_int32_t num){
    u_int32_t b0,b1,b2,b3;
    u_int32_t res;

    b0 = (num & 0x000000ff) << 24u;
    b1 = (num & 0x0000ff00) << 8u;
    b2 = (num & 0x00ff0000) >> 8u;
    b3 = (num & 0xff000000) >> 24u;

    res = b0 | b1 | b2 | b3;
    return res;
}
```

Now to apply that function to each bytes of our message schedule :

```c
void change_message_schedule_endian(u_int32_t* message_schedule, u_int32_t lenght_message_schedule){
    for (int i = 0; i < lenght_message_schedule; i++){
        message_schedule[i] = endian_converter(message_schedule[i]);
    }
}
```

We finally have our endian correct message schedule !

## Initializing hash values

We then have to initialize some hash values which will just be some starting values for our digest. Those hash values will be obtained by taking the frationnal part of the square root of the first 8 prime numbers. I know that last sentence was scary. Let's first make this a mathematical formula :

$$
\begin{equation}
h_n = frac(\sqrt{p},\;\forall p \in \{ 2,3,5,7,11,13,17,19 \})
\end{equation}
$$

Okay, now, for each of those prime number in $$\{2,3,5,7,11,13,17,19\}$$, we will compute their square root which gives us the following:

$$
\begin{align}
h_0 &= \sqrt{2} = 1.41421356237\\
h_1 &= \sqrt{3} = 1.73205080757\\
&...\\
h_7 &= \sqrt{19} = 4.35889894354\\
\end{align}
$$

We then only keep the fractionnal part (which is the $$frac(...)$$ of the formula) :

$$
\begin{align}
h_0 &= 41421356237\\
h_1 &= 73205080757\\
&...\\
h_7 &= 35889894354
\end{align}
$$

We finally translate those fractionnal part to binary and only keep the first 32 bits (8 first hex numbers) and set them as hexadecimal. If we look at the fractional part of $$h_0$$ , we have :

$$
\begin{align}
h_{0} &= 41421356237{...}\\
&= 6a09e667f0559b438{...}\\
&= 6a09e667
\end{align}
$$

We now do the same for all those values from $$h_0$$ to $$h_7$$. We then get the followings :

$$
\begin{align}
h_0 &=6a09e667\\
h_1 &=bb67ae85\\
h_2 &=3c6ef372\\
h_3 &=a54ff53a\\
h_4 &=510e527f\\
h_5 &=9b05688c\\
h_6 &=1f83d9ab\\
h_7 &=5be0cd19
\end{align}
$$

## Some more definition of constants

Similar to previously computed hash values, we now need to compute 64 more. These 64 values are the fractionnal part of cube root of the first 64 prime number we need to find this :

$$
\begin{equation}
h_n = frac(\sqrt[3]{p},\;\forall p \in \{ 2,3,5,7,11, {...}, 311\})
\end{equation}
$$

After computing them, we get those constants:

```
k0 to k7 :   0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
k8 to k15 :  0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
k16 to k23 : 0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
k24 to k31 : 0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
k32 to k39 : 0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
k40 to k47 : 0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
k48 to k55 : 0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
k56 to k63 : 0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
```

# Defining required functions

The hash algorithm requires the following specific functions :
- $$Maj(a,b,c)$$.
- $$Ch(a,b,c)$$.
- $$\sigma_0(x)$$.
- $$\sigma_1(x)$$.
- $$\Sigma_0(x)$$.
- $$\Sigma_1(x)$$.

We will go in detail for each function on what they are and on how to implement them.

## Maj(a,b,c)

$$Maj(a,b,c)$$ is a bitwise function that stands for "Majority". For each bit at the same index of the three inputs, it will output the majority of bits.

For example, let's say that at the first index, $$a$$ has a 1, $$b$$ has a 0 and $$c$$ has a 1. The output at the first index will then be a 1 because there is more 1 than 0.
Let's say now that at the second index, $$a$$ has a 0, $$b$$ has a 0 and $$c$$ has a 1. The output at the second index will be a 0 because there is more 0 than 1.

We can now make a truth table for this function at any index :


| $$a$$ | $$b$$ | $$c$$ | $$Maj(a,b,c)$$ |
| :---: | :---: | :---: | :---: | 
| 0 | 0 | 0 | 0 |
| 0 | 0 | 1 | 0 |
| 0 | 1 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 0 | 0 |
| 1 | 0 | 1 | 1 |
| 1 | 1 | 0 | 1 |
| 1 | 1 | 1 | 1 |

Now that we have the truth table, we can make the Karnaugh table and figure out what the equation is

| $$a$$ (lines) / $$b.c$$ (rows) | 00 | 01 | 11 | 10 |
| :-: | :-: | :-: | :-: | :-: | 
| 0 | 0 | 0 | 1 | 0 |
| 1 | 0 | 1 | 1 | 1 |

We can now figure out what the equation of $$Maj(a,b,c)$$ is (where $$.$$ is an AND, $$+$$ is an OR and $$\oplus$$ is a XOR):

$$
\begin{equation}
S = a.c + a.b + b.c
\end{equation}
$$

We can see online that the equation of $$Maj(a,b,c)$$ is $$S_{online}= a.c \oplus a.b \oplus b.c$$. But this solution with the $$\oplus$$ is strictly equivalent to our solution. We could prove it thanks to boolean algebrae, but I am way too lazy for that, so here is the truth table of both the solutions, proving that both equation are valid :

| $$a$$ | $$b$$ | $$c$$ | $$S$$ | $$S_{online}$$ |
| :---: | :---: | :---: | :---: | :---: |
| 0 | 0 | 0 | 0 | 0 |
| 0 | 0 | 1 | 0 | 0 |
| 0 | 1 | 0 | 0 | 0 |
| 0 | 1 | 1 | 1 | 1 |
| 1 | 0 | 0 | 0 | 0 |
| 1 | 0 | 1 | 1 | 1 |
| 1 | 1 | 0 | 1 | 1 |
| 1 | 1 | 1 | 1 | 1 |

Henceforth, we will take our solution as valid and say this : $$Maj(a,b,c) = a.c + a.b + b.c$$

Now that we've defined the equation of $$Maj(a,b,c)$$, writing the code, is naught but a piece of cake :

```c
u_int32_t maj (u_int32_t a, u_int32_t b, u_int32_t c){    
    u_int32_t wout = (a&b) | (a&c) | (b&c);
    return wout;
}
```

## Ch(a,b,c)

$$Ch(a,b,c)$$ is a bitwise operator that stands for "Choose". For each bit of the inputs at the same index, the bit of a will choose wether the output bit is the bit from c or the bit from b. So we have :

$$
\begin{equation}
    Ch(a,b,c) =
    \begin{cases}
        b &,\text{if } a=1\\
        c &,\text{if } a=0
    \end{cases}
\end{equation}
$$

Once again, let's make a truth table and let's try to find the underlying equation of this function

| $$a$$ | $$b$$ | $$c$$ | $$Ch(a,b,c)$$ |
| :---: | :---: | :---: | :---: | 
| 0 | 0 | 0 | 0 |
| 0 | 0 | 1 | 1 |
| 0 | 1 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 0 | 0 |
| 1 | 0 | 1 | 0 |
| 1 | 1 | 0 | 1 |
| 1 | 1 | 1 | 1 |

Now for the Karnaugh table

| $$a$$ (lines) / $$b.c$$ (rows) | 00 | 01 | 11 | 10 |
| :-: | :-: | :-: | :-: | :-: | 
| 0 | 0 | 1 | 1 | 0 |
| 1 | 0 | 0 | 1 | 1 |

Let's find that damned equation !

$$
\begin{equation}
S = a.b + \bar{a}.c
\end{equation}
$$

Once again, we find the same equation with the $$\oplus$$ online Like so : $$S_{online} = a.b \oplus \bar{a}.c$$. Once again, these equation are strictly equal (I'm not going to prove it again), but $$S \equiv S_{online}$$.

We can now write the following code :

```c
u_int32_t ch (u_int32_t a, u_int32_t b, u_int32_t c){    
    u_int32_t wout = (a&b) | ((~a)&c);
    return wout;
}
```

## The $$\sigma_{\{0,1\}}(x)$$ and $$\Sigma_{\{0,1\}}(x)$$ functions

These functions are nothing but successive rotations and bit shifting of 32 bit numbers. I do not know why any of these function are the way they are, but they are easily implemented since there is no inherently complexe operations done here. So let's get down to business and implement them.

### $$\sigma_0(x)$$

$$\sigma_0(x)$$ is the following :

$$
\begin{equation}
\sigma_0(x)=rightrotate(x,7) \oplus leftrotate(x,14) \oplus rightshift(x,3)
\end{equation}
$$

```c
u_int32_t sig0 (u_int32_t w){
    u_int32_t w1 = w >> 7  | w << 25;
    u_int32_t w2 = w >> 18 | w << 14;
    u_int32_t w3 = w >> 3;

    u_int32_t wout = w1 ^ w2 ^ w3;

    return wout;
}
```

### $$\sigma_1(x)$$

$$\sigma_1(x)$$ is the following :

$$
\begin{equation}
\sigma_1(x)=leftrotate(x,15) \oplus leftrotate(x,13) \oplus rightshift(x,10)
\end{equation}
$$

```c
u_int32_t sig1 (u_int32_t w){
    u_int32_t w1 = w >> 17 | w << 15;
    u_int32_t w2 = w >> 19 | w << 13;
    u_int32_t w3 = w >> 10;

    u_int32_t wout = w1 ^ w2 ^ w3;

    return wout;
}
```

### $$\Sigma_0(x)$$

$$\Sigma_0(x)$$ is the following :

$$
\begin{equation}
\Sigma_0(x)=rightrotate(x,2) \oplus rightrotate(x,13) \oplus leftrotate(x,10)
\end{equation}
$$

```c
u_int32_t SIG0 (u_int32_t w){
    u_int32_t w1 = w >> 2  | w << 30;
    u_int32_t w2 = w >> 13 | w << 19;
    u_int32_t w3 = w >> 22 | w << 10;

    u_int32_t wout = w1 ^ w2 ^ w3;

    return wout;
}
```

### $$\Sigma_1(x)$$

$$\Sigma_1(x)$$ is the following :

$$
\begin{equation}
\Sigma_1(x)=rightrotate(x,6) \oplus rightrotate(x,11) \oplus leftrotate(x,7)
\end{equation}
$$

```c
u_int32_t SIG1 (u_int32_t w){
    u_int32_t w1 = w >> 6  | w << 26;
    u_int32_t w2 = w >> 11 | w << 21;
    u_int32_t w3 = w >> 25 | w << 7 ;

    u_int32_t wout = w1 ^ w2 ^ w3;

    return wout;
}
```

# Computing the hash

Now that our message schedule is operational, our constants are proper, our starting hash values are set and our specific function defined, it is time to finally compute that hash!

The algorithm given by our brother mathematician is this :

> $$K$$ is the array of constant defined [here](https://kyllano.github.io/posts/sha256-mumbo-jumbo/#some-more-definition-of-constants)
$$W$$ is the message schedule array 
$$H_{[0;7]}^{0}$$ are the starting hash values computed [here](https://kyllano.github.io/posts/sha256-mumbo-jumbo/#initializing-hash-values)
For $$i$$ starting from 1, ending at $$N$$, the number of message block of the message schedule $$W$$(since the message schedule is a block paddded with 0s) :
<br>$$\quad$$$$\quad$$ Fill the message schedule $$W_t$$ from 0 to 63 with these instructions :
<br>$$\quad$$$$\quad$$$$\quad$$$$\quad$$$$
\begin{equation}
    W_t =
    \begin{cases}
        W_t &,\text{if } 0 \leq t \leq 15\\
        \sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16} &,\text{if } 16 \leq t \leq 63
    \end{cases}
\end{equation}
$$
<br>$$\quad$$$$\quad$$If it is the first block, initialize a,b,c,d,e,f,g with the initial hash values $$H_{[0;7]}^{0}$$. Otherwise, just initialize them with the updated hash values $$H_{[0;7]}^{i-1}$$:
<br>$$\quad$$$$\quad$$$$
\begin{align}
a &=H_0^{i-1}\\
b &=H_1^{i-1}\\
c &=H_2^{i-1}\\
d &=H_3^{i-1}\\
e &=H_4^{i-1}\\
f &=H_5^{i-1}\\
g &=H_6^{i-1}\\
h &=H_7^{i-1}
\end{align}
$$
<br>$$\quad$$$$\quad$$for t starting from 1, ending at 63 :
<br>$$\quad$$$$\quad$$$$\quad$$$$\quad$$do:
<br>$$\quad$$$$\quad$$$$\quad$$$$\quad$$
$$
\begin{align}
&T_1 = h + \Sigma_1(e) + Ch(e,f,g) + K_t + W_t\\
&T_2 = \Sigma_0(a) + Maj(a,b,c)\\
&h=g\\
&g=f\\
&f=e\\
&e=d+T_1\\
&d=c\\
&c=b\\
&b=a\\
&a=T_1+T_2
\end{align}
$$
<br>$$\quad$$$$\quad$$Update the hash values :
<br>$$\quad$$$$\quad$$$$
\begin{align}
H_0^{i} &= a + H_0^{i-1}\\
H_1^{i} &= b + H_1^{i-1}\\
H_2^{i} &= c + H_2^{i-1}\\
H_3^{i} &= d + H_3^{i-1}\\
H_4^{i} &= e + H_4^{i-1}\\
H_5^{i} &= f + H_5^{i-1}\\
H_6^{i} &= g + H_6^{i-1}\\
H_7^{i} &= h + H_7^{i-1}
\end{align}
$$
<br>In the end, you just have to concatenate the last hash values H_{[0;7]}^{i} and you get the end sha.

Well the algorithm is there, it's now only a matter of writing it in C. Thus, we produce this code :

```c
u_int32_t* compute_sha (u_int32_t* message_schedule, u_int32_t lenght_message_schedule){
    u_int32_t hash[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for (u_int32_t bloc_i = 0; bloc_i < (lenght_message_schedule/64); bloc_i ++){
        for (int i=16; i < 64; i++){
            u_int32_t w1 = message_schedule[64*bloc_i + i-16];
            u_int32_t w2 = sig0(message_schedule[64*bloc_i + i-15]);
            u_int32_t w3 = message_schedule[64*bloc_i + i-7];
            u_int32_t w4 = sig1(message_schedule[64*bloc_i + i-2]); 
            message_schedule[64*bloc_i + i] = w1+w2+w3+w4;
        }

        //initialisation of our variables
        u_int32_t a = hash[0];
        u_int32_t b = hash[1];
        u_int32_t c = hash[2];
        u_int32_t d = hash[3];
        u_int32_t e = hash[4];
        u_int32_t f = hash[5];
        u_int32_t g = hash[6];
        u_int32_t h = hash[7];

        for (u_int32_t i =0; i < 64; i++){
            u_int32_t temp1 = h + SIG1(e) + choice(e,f,g) + k[i] + message_schedule[64*bloc_i + i];
            u_int32_t temp2 = SIG0(a) + maj(a,b,c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] = a + hash[0];
        hash[1] = b + hash[1];
        hash[2] = c + hash[2];
        hash[3] = d + hash[3];
        hash[4] = e + hash[4];
        hash[5] = f + hash[5];
        hash[6] = g + hash[6];
        hash[7] = h + hash[7];
    }

    u_int32_t* output = malloc(sizeof(u_int32_t) * 8);
    output[0] = hash[0];
    output[1] = hash[1];
    output[2] = hash[2];
    output[3] = hash[3];
    output[4] = hash[4];
    output[5] = hash[5];
    output[6] = hash[6];
    output[7] = hash[7];

    return output;
}
```

Well looks like we are nearing the end. Now it is only a matter of making the function that takes all the preprocessing we've done before and concatenate the output. It's just putting it all together if you will 

```c
/*
    Please make sure your output is 65 bytes (64 hex characters + '\0')
*/
void create_sha(unsigned char* input, unsigned char* output){
    //keeping track of the lenghts
    u_int64_t lenght_message_block;
    u_int32_t lenght_message_schedule;

    //creating the message block and then creating the message schedule from the message block
    unsigned char * message_block = str_to_message_block(input, &lenght_message_block);
    u_int32_t* message_schedule = create_message_schedule(message_block, &lenght_message_schedule, lenght_message_block);

    //right now the message schedule is in big endian. If our system is in little endian, we need to make the schedule in little endian as well
    int isLittleEndian = 1;
    if (*((char *)&isLittleEndian) == 1) change_message_schedule_endian(message_schedule, lenght_message_schedule);
    
    //finally, we compute the actual sha
    u_int32_t* sha = compute_sha(message_schedule, lenght_message_schedule);
    
    //We store te formatted string
    sprintf((char*) output, "%08x%08x%08x%08x%08x%08x%08x%08x",sha[0],sha[1],sha[2],sha[3],sha[4],sha[5],sha[6],sha[7]);
    
    //I love my memory, and I respect it
    free(message_schedule);
    free(message_block);
    free(sha);
}
```
With that, we only need to use the function like this in this simple program :

```c
#include "sha256.h"

int main(int argc, char const *argv[])
{
    unsigned char input [] = "Hi, How are ya?";
    unsigned char output [64];
    create_sha(input, output);
    printf("sha256 of "%s" : %s\n", input, output);
    return 0;
}
```
We will then get this output :
```
sha256 of "sha256 rocks!" : a0c5c16ff00f28798890250d028f3784d6f488df9cbbb5330e55c7391a7db7a3
```

# Closing thoughts

Well this all has been an adventure, I must say that not explaining our choice of functions, constants and such can look like we are taking steps in the dark, but as I have told it before, I probably will not get into the *why* of sha256 because I do not yet have the mathematical baggage needed to grasp some of those concepts. But in time, I probably will understand those. In the meantime, I keep on searching on the subject if it interest you with questions such as "how is sha512 different?", "What could have been done differently to make it even more secure?", "Why do some people add salt to sha?" and so on.

If you have any question or want to point out a typo or an error, don't hesitate to hit me up on discord at Kyll#2689

See you in the next one !