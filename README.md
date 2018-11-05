# Netcreeper

A netfilter hack to beat the JIO Censorship (Netsweeper) in India

## What does it really do?

Drops RST packets based on their TTL Value.

## How does it do that?

Uses netfilterqueue module in python to process on incoming packets

## What is kernel_module folder about?

So the python implementation is slow, as expected. Kernel module is (obviously) written in C and would speed up the process. However, its not near completion yet. Feel free to chip in.

## So does it only works on Jio?

It should work for any implementation of Netsweeper's RST packet injection, Jio being one of it's clients. I've only tested it on Jio.

## Does it work anymore?

Unfortunately, No. A few days before pushing out this code, I found out that Jio had changed it's censorship mechanism. Instead of a centralized mechanism, with the censor placed at around 6-8 hops away, the censor was placed much closer. This hints at a decentralized system.

## Can I have more information?

Sure, go to: https://jvsg.github.io/blog/2018/censorship-on-jio/
