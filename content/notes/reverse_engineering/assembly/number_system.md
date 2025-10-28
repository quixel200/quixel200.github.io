+++
date = '2025-10-28T08:22:25+05:30'
draft = false
title = 'Number Systems'
+++

Each base follows a pattern and you can clearly see that from the examples.

# Hexadecimal (Base 16)

Each digit can represent upto 16, 0-9 and then A-F(for 10 to 16).

```
0x2f is 48 in decimal

    2                f
(16^1)*2  + (16^0)*16(f = 16)
```


# Decimal (Base 10)

The one we're all familiar with, numbers 0-9. Pretty self explanatory. 

```
25 

    2           5
(10^1)*2  + (10^0)*5
```

# Octal (Base 8)

Contains numbers 0-7, each digit representing 3 bits. If you're familiar with Linux file permissions you already know Octal.

```
10 in decimal would be represented as 12 in octal 

  1           2
(8^1)*1  + (8^0)*2
```

# Binary (Base 2)

Contains just 0 and 1, really useful when working with circuits and can represent a on/off state.

```
101 in binary is 5 in decimal

   1         0        1
(2^2)*1 + (2^1)*0 + (2^0)*1
```

## Why so many?

Binary is most useful when dealing with computers as circuits can only represent 2 states at a time, one being on and another being off.


You might occasionally see Octal being used, the best example I can think of is file permissions in Linux.


Hexadecimal is very extensively used to represent memory or values in a system as these values can get very huge.


For example 64GB in bytes is 68,719,476,736.
In hexadecmial? `0x1000000000`. 
As you can see it is much easier to read and represent hexadecimal numbers once you get used to them.
