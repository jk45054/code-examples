from binascii import hexlify, unhexlify

class RC4:
    S = None
    i = 0
    j = 0
    dropped = 0
    # constructor for instance of class RC4
    # if n > 0, drop first n key bytes - alias RC4-drop[n]
    def __init__(self, keybytes, n=0):
        self.i = 0
        self.j = 0
        self.S = bytearray(256)
        self.KSA(keybytes)
        while n > 0:
            self.PRGA()
            n = n - 1
    # Key Scheduling Algorithm (KSA)
    def KSA(self, key):
        for i in range(256):
            self.S[i] = i
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    # Pseudo-random generation algorithm (PRGA)
    def PRGA(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return (self.S[(self.S[self.i] + self.S[self.j]) % 256])
    def crypt(self, data):
        result = bytearray()
        for b in data:
            result.append(b ^ self.PRGA())
        return(result)

