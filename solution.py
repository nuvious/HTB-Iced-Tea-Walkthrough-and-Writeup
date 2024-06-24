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

