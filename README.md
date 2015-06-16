luisilrt
========

A small variant of the CLR made by [luis140219](https://github.com/luis140219). Documentation is also available.

This is also a position-independent DLL. If the DLL is allocated at a different address it works fine.
I've chosen that because adding relocations to address-unstable code longer than 4K is hard for humans to do in the code,
so I've chosen this DLL to be position-independent.
