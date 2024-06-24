
# HTB - Iced Tea Solution/Walkthrough

- [Requirements](#requirements)
- [Recon](#recon)
- [Writing a Decrypt Function](#writing-a-decrypt-function)
- [Getting the Flag](#getting-the-flag)
- [Appendices](#appendices)
  - [Appendix A - Cipher Source w/o CBC](#appendix-a---cipher-source-wo-cbc)
  - [Appendix B - Final Solution Code](#appendix-b---final-solution-code)

## Requirements

First thing to get out of the way is to install the required cryptographic library:

```bash
pip3 install pycryptodome
```

## Recon

First thing to do is to preserve the output file for the challenge:

```bash
cp output.txt output.txt.original
```

Now we can create a `secret.py` file to test out the encryption function:

```bash
cat > secret.py << EOF
FLAG=b'HTB{this_is_a_test_flag}'
EOF
```

Running the source with `python3 source.py` we get the following output in `output.txt`:

```plaintext
Key : bdda0bd3598ed634e306bf1c80079d5d
Ciphertext : db66762c67d553c3580bef46e8657a39bf40f7e2bc5127f8c594a23ad99210d1
```

Looking at the `__main__` logic:

```python
if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
```

We the `Cipher` instance isn't instantiated with a declared mode which means it defaults to `Mode.ECB`. Given that,
let's strip out any of the CBC logic as well as the `_xor` function which isn't referenced anywhere in the code.
The full reduced code is in [**Appendix A**](#appendix-a).

Looking at the members of the `Cipher` class, we have:

|Member|Value|
|-|-|
|BLOCK_SIZE|64|
|KEY|The key divided into 4, 4 byte/32 bit blocks|
|DELTA|0x9e3779b9|

The encrypt function pads and divides the message into 8 byte blocks and then encrypts them with the `encrypt_block` function:

```python
    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]

        ct = b''
        for pt in blocks:
            ct += self.encrypt_block(pt)
        return ct
```

The `encrypt_block` function splits each 8 byte block into two 4 byte blocks; `m0` and `m1`:

```python
    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        ...
```

It also generates a 32 bit mask of 1's:

```python
    def encrypt_block(self, msg):
        ...
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
        ...
```

Finally the guts of the encryption. Over 32 rounds, a value s is incremented by `self.DELTA` each round. A series of
operations are performed, shifting blocks, adding components of the key and XORing against the opposing message block
with the s value:

```python
    def encrypt_block(self, msg):
        ...
        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk

        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)
```

## Writing a Decrypt Function

This approach will simply try to reverse the `encrypt_block` function. We can extend the `Cipher` class add the
decryption logic.

```python
from source import Cipher
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b


class CipherWithDecrypt(Cipher):
    ...
```

The `decrypt` function is straightforward and just needs to chunk the cipher text into 8 byte blocks and run them into
a `decrypt_block` function:

```python
class CipherWithDecrypt(Cipher):
    ...
    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8]
                  for i in range(0, len(ct), self.BLOCK_SIZE//8)]

        pt = b''
        for block in blocks:
            pt += self.decrypt_block(block)

        return unpad(pt, self.BLOCK_SIZE//8)
```

Finally, we write the `decrypt_block` function. Key points are that `s` needs to be initialized at its final value
in the `encrypt_block` function. Then we need to reverse the `m = m0 || m1` logic to split `m0` and `m1` into separate
parts.

```python
class CipherWithDecrypt(Cipher):
    ...
    def decrypt_block(self, ct):
        m = b2l(ct)
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = self.DELTA << 5

        m1 = m & msk
        m0 = (m >> (self.BLOCK_SIZE//2)) & msk
```

Next we execute the 32 rounds, inverting the logic by manipulating `m1` before `m0` and replacing `+=` operators with
`-=` operators. This is a naive approach, but the results speak for themselves.

```python
class CipherWithDecrypt(Cipher):
    ...
    def decrypt_block(self, ct):
        ...
        K = self.KEY

        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA

        pt = l2b((m0 << 32) + m1)

        return pt
```

## Getting the Flag

Finally we add some logic to read in the `output.txt`, extract the key and ciphertext and run it through the decryption
function:

```python
if __name__ == '__main__':
    with open('output.txt', 'r') as f:
        key_str = f.readline().split(":")[1].strip()
        ct_str = f.readline().split(":")[1].strip()
        key = bytes.fromhex(key_str)
        ct = bytes.fromhex(ct_str)
        cipher = CipherWithDecrypt(key)
        pt = cipher.decrypt(ct)
        print(pt)
```

Run against our test flag we get the desired output:

```bash
┌──(nuvious㉿kalinubflex)-[~/Downloads/crypto_iced_tea]
└─$ python3 solution.py 
b'HTB{this_is_a_test_flag}'
```

Then to get the flag we simply need to restore the original output and run the solution one more time:

```bash
┌──(nuvious㉿kalinubflex)-[~/Downloads/crypto_iced_tea]
└─$ mv output.txt.original output.txt && python3 solution.py 
b'HTB{n0t_th3_r3al_fl@g_0bv1ou5ly}'
```

Full source for the solution is provided in [**Appendix B**](#appendix-b).

## Appendices

### Appendix A - Cipher Source w/o CBC

```python
import os
from secret import FLAG
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b


class Cipher:
    def __init__(self, key):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]

        ct = b''
        for pt in blocks:
            ct += self.encrypt_block(pt)
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk

        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)


if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
```

### Appendix B - Final Solution Code

```python
from source import Cipher
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b


class CipherWithDecrypt(Cipher):
    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8]
                  for i in range(0, len(ct), self.BLOCK_SIZE//8)]

        pt = b''
        for block in blocks:
            pt += self.decrypt_block(block)

        return unpad(pt, self.BLOCK_SIZE//8)

    def decrypt_block(self, ct):
        m = b2l(ct)
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        # s is incremented 32 times in the encrypt function so we need to start
        # it at self.DELTA << log(32,2) or 5
        s = self.DELTA << 5

        # Next we need to reverse the m = m0 || m1
        m1 = m & msk
        m0 = (m >> (self.BLOCK_SIZE//2)) & msk

        K = self.KEY

        # Now we invert the operations by using -= instead of += and operate on m1 first, then m0. This is a naive
        # approach, but the results speak for themselves
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA

        # Finally, we need to move m0 back to the front and append m1
        pt = l2b((m0 << 32) + m1)

        return pt

if __name__ == '__main__':
    with open('output.txt', 'r') as f:
        key_str = f.readline().split(":")[1].strip()
        ct_str = f.readline().split(":")[1].strip()
        key = bytes.fromhex(key_str)
        ct = bytes.fromhex(ct_str)
        cipher = CipherWithDecrypt(key)
        pt = cipher.decrypt(ct)
        print(pt)
```
