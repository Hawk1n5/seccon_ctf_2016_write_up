# jmper

## 0x0 Introduction

```
jmp/jmper: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=9fce8ae11b21c03bf2aade96e1d763be668848fa, not stripped
```

```
[*] '/root/ctf/seccon_ctf_2016/pwn/jmp/jmper'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

This binary is Full RELRO and NX

## 0x1 Vulnerability

This binary has 6 feature like : 

```
Welcome to my class.
My class is up to 30 people :)
1. Add student.
2. Name student.
3. Write memo
4. Show Name
5. Show memo.
6. Bye :)
```

- Add student : if student > 30 then call longjmp
    - when add a student it will do this

      [0x400893] malloc(48) (memo)    = 0x6031e0

      [0x4008b1] malloc(32) (name)    = 0x603220
- Write student name
- Write student memo
    - there have one-by-overwrite
    ```
    0x6031e0:	0x0000000000000000	0x6161616161616161
    0x6031f0:	0x6161616161616161	0x6161616161616161
    0x603200:	0x6161616161616161	0x0000000000603261
    ```
    it will overwrite student's name address

    so it can do leak information and overwrite stack
    
- Show Name
- Show memo
- exit

because this binary have Full RELRO so can't do got hajack.

but it have a function setjmp. it set some register info in heap

```
0x603100:	0x0000000000000000	0x00000000000000d1
0x603110:	0x0000000000000000	0x84ab92040d83e2fd
0x603120:	0x0000000000400730	0x00007fffffffe580
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x84ab92040de3e2fd	0x7b546d7bdca1e2fd
```
0x603140 is a encrypto rsp when call longjmp

decrypto method is :
```
(rip_s.rrot64(0x11)^setjmp) ^ rsp_s.rrot64(0x11)+0x10
```

and you will get return address and overwrite to your ROPgadget!

[payload](exp.rb)



