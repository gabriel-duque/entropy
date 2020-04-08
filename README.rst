entropy
=======

Introduction
------------

entropy is a Python3 library you can use to generate ROP chains. For a basic
background on return oriented programming (ROP), you can read this light
`explanation`_.

In a nutshell, ROP is a modern exploit technique. In the old days, people used
to abuse the fact that program stacks were executable. Once a vulnerability was
found, attackers would write the code they wanted to execute on the stack then
rewrite the return address of the function to have the program jump onto their
code and execute it.

To mitigate this technique, the stack was marked as non-executable so this
strategy wouldn't work anymore. In a general manner, we now enforce a general
rule (or we should if we don't yet) called *W^X* (write xor execute). What this
means is that no memory zone will be *executable* and *writeable* which means
attackers cannot execute code they write.

The only way to run some code when *W^X* is enforced is to reuse existing code
in executable segments.

This is where ROP starts making sense.

ROP is the concept of reusing small `basic blocks`_ we will call *gadgets* to
execute the sequence of code we want. ROP is all about the bigger picture.

If you already know about how ROP works you can just skip to the next part
about ROP mitigation.

We are going to go through a simple example of how ROP works.

.. _explanation: https://en.wikipedia.org/wiki/Return-oriented_programming
.. _basic blocks: https://en.wikipedia.org/wiki/Basic_block

ROP mitigation
--------------

In order to keep people from exploit programs with ROP chains, some people over
in the OpenBSD project tried creating some mitigations.

Two of them prevailed and are now used system-wide on OpenBSD machines:

* reducing the number of ``ret`` instructions

* adding a new type of protector on the stack: retguards