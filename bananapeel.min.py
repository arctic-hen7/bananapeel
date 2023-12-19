'''
MIT License

Copyright (c) 2023 Sam Brew

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

P='i'
O='n'
N='b'
M='q'
L='r'
H=len
E='s'
import sys,base64 as J,struct as Q
A=[A.strip()for A in sys.stdin.readlines()]
F=dict(zip([L,M,N,O],Q.unpack('<QQII',J.b64decode(sys.argv[1])[:24])))
B=lambda x,limit:x%(limit+1)
def I(rng):C=rng;A=C[E];C[E]=B(A*0x5851f42d4c957f2d+(C[P]|1),0xffffffffffffffff);D=B((A>>18^A)>>27,4294967295);F=B(A>>59,4294967295);return B(D>>F|D<<(-F&31),4294967295)
D={E:0,P:B(F[M]<<1|1,0xffffffffffffffff)}
I(D)
D[E]=B(D[E]+F[L],0xffffffffffffffff)
I(D)
C=0
while C<H(A):
	R=I(D);K=f"{R:08x}"
	for G in range(C,H(A)):
		if A[G].startswith(K):S=A[G][H(K):][F[O]:];A[G],A[C]=A[C],A[G];A[C]=S;C+=1
print(J.urlsafe_b64decode(bytes.fromhex(''.join(A)[:-1]if H(''.join(A))%2!=0 else''.join(A))[:F[N]]).decode('utf-8'))
