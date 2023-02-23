---
title: sha256 mumbo jumbo
date: 2023-01-18 12:59 +0100
categories: [Cybersecurity]
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

## String to message block

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
# Computing the hash

## Required functions

The hash algorithm requires the following specific functions :
- $$Maj(a,b,c)$$.
- $$Ch(a,b,c)$$.
- $$\sigma_0(x)$$.
- $$\sigma_1(x)$$.
- $$\Sigma_0(x)$$.
- $$\Sigma_1(x)$$.

We will go in detail for each function on what they are and on how to implement them.

### Maj(a,b,c)

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

### Ch(a,b,c)

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

### The $$\sigma_{\{0,1\}}(x)$$ and $$\Sigma_{\{0,1\}}(x)$$ functions

These functions are nothing but successive rotations and bit shifting of 32 bit numbers. I do not know why any of these function are the way they are, but they are easily implemented since there is no inherently complexe operations done here. So let's implement these functions

#### $$\sigma_0$$

$$\sigma_0(x)$$ is the following :

$$
\begin{equation}
\sigma_0(x)=rightrotate(x,7)+leftrotate(x,14)+rightshift(x,10)
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