#!/usr/bin/python
#_*_ coding:utf8 _*_

from libnum import n2s, s2n
import gmpy2
import binascii
import time
import Crypto.Util.number as cryptos
from Crypto.Random import random
from Crypto.Util.number import getPrime


# 工具函数#
def gcd(a, b):
    if (b == 0):
        return a
    return gcd(b, a % b)


class FHE_Cyrpto:
    m = 0
    c1 = 0
    c2 = 0
    p1 = 0
    q1 = 0
    p2 = 0
    q2 = 0
    rp2 = 0
    rq2 = 0
    p2rp2 = 0
    q2rq2 = 0
    s1 = 0
    t = 0
    n1 = 0
    n2 = 0
    n12 = 0
    len1 = 0
    len2 = 0
    lambdas1 = 0
    lambdas2 = 0
    r1 = 0
    r2 = 0
    r3 = 0
    r4 = 0
    r1p2 = 0
    r2q2 = 0
    r3n12 = 0
    r4n12 = 0
    enc_time = 0
    dec_time = 0

    def fhe_myExtGCD(self, a, b):
        """
        a: 模的取值
        b: 想求逆的值
        """
        if (b == 0):
            return 1, 0, a
        x, y, gcd = self.fhe_myExtGCD(b, a % b)
        return y, x - a // b * y, gcd

    # Fhe密钥生成
    #我的版本
    def fhe_get_key(self, len1, len2, lambdas1, lambdas2):
        self.len1 = len1
        self.len2 = len2
        self.lambdas1 = lambdas1
        self.lambdas2 = lambdas2
        # self.n1,n2,t是公开的
        self.p1 = cryptos.getPrime(self.len1)
        self.q1 = cryptos.getPrime(self.len1)
        while self.q1 == self.p1:
            self.q1 = cryptos.getPrime(self.len1)

        self.p2 = cryptos.getPrime(self.len2)
        while self.p2 == self.q1 or self.p2 == self.p1:
            self.p2 = cryptos.getPrime(self.len2)

        self.q2 = cryptos.getPrime(self.len2)
        while self.q2 == self.p2 or self.q2 == self.q1 or self.q2 == self.p1:
            self.q2 = cryptos.getPrime(self.len2)

        self.s1 = cryptos.getRandomNumber(self.len2)

        self.r1 = cryptos.getRandomNumber(self.lambdas2)
        self.r2 = cryptos.getRandomNumber(self.lambdas2)
        self.r3 = cryptos.getRandomNumber(self.lambdas1)
        self.r4 = cryptos.getRandomNumber(self.lambdas1)

        self.n1 = self.p1 * self.q1
        self.n2 = self.p2 * self.q2
        self.n12 = self.n1 * self.n2
        self.t = self.n12 * self.s1
        self.r3n12 = self.r3 * self.n12
        self.r4n12 = self.r4 * self.n12

        self.rp2, self.rq2, gcdnumber = self.fhe_myExtGCD(self.p2, self.q2)

        if self.rp2 < 0:
            self.rp2 = self.rp2 + self.q2
        else:
            self.rq2 = self.rq2 + self.p2

        self.p2rp2 = self.p2 * self.rp2
        self.q2rq2 = self.q2 * self.rq2
        self.r1p2 = self.r1 * self.p2
        self.r2q2 = self.r2 * self.q2
        return self.n1, self.n2, self.t, self.p1, self.q1, self.p2, self.q2, self.s1, self.rp2, self.rq2, self.r1, self.r2, self.r3, self.r4

    # Fhe密钥生成
    #caolaoshi版本
    def fhe_cao_get_key(self, len1, len2, lambdas1, lambdas2):
        self.len1 = len1
        self.len2 = len2
        self.lambdas1 = lambdas1
        self.lambdas2 = lambdas2
        # self.n1,n2,t是公开的
        self.p1 = cryptos.getPrime(self.len1)
        self.q1 = cryptos.getPrime(self.len1)
        while self.q1 == self.p1:
            self.q1 = cryptos.getPrime(self.len1)

        self.p2 = cryptos.getPrime(self.len2)
        while self.p2 == self.q1 or self.p2 == self.p1:
            self.p2 = cryptos.getPrime(self.len2)

        self.q2 = cryptos.getPrime(self.len2)
        while self.q2 == self.p2 or self.q2 == self.q1 or self.q2 == self.p1:
            self.q2 = cryptos.getPrime(self.len2)

        self.s1 = cryptos.getRandomNumber(self.len2)

        self.r1 = cryptos.getRandomNumber(self.lambdas2)
        self.r2 = cryptos.getRandomNumber(self.lambdas2)
        self.r3 = cryptos.getRandomNumber(self.lambdas1)
        self.r4 = cryptos.getRandomNumber(self.lambdas1)

        self.n1 = self.p1 * self.q1
        self.n2 = self.p2 * self.q2
        self.t = self.n1 * self.s1

        self.rp2, self.rq2, gcdnumber = self.fhe_myExtGCD(self.p2, self.q2)

        if self.rp2 < 0:
            self.rp2 = self.rp2 + self.q2
        else:
            self.rq2 = self.rq2 + self.p2

        self.p2rp2 = self.p2 * self.rp2
        self.q2rq2 = self.q2 * self.rq2
        self.r1p2 = self.r1 * self.p2
        self.r2q2 = self.r2 * self.q2
        return self.n1, self.n2, self.t, self.p1, self.q1, self.p2, self.q2, self.s1, self.rp2, self.rq2, self.r1, self.r2, self.r3, self.r4

    # Fhe加解密函数
    # 我的
    def fhe_encryt(self, m):
        return (((m % self.p2 + self.r1p2) % self.n2 + self.r3n12) % self.t,
                ((m % self.q2 + self.r2q2) % self.n2 + self.r4n12) % self.t)

    def fhe_decryt(self, c1, c2):
        return ((c1 % self.n12) % self.p2 * self.q2rq2 + (c2 % self.n12) % self.q2 * self.p2rp2) % self.n2  # 这个解密更快
        # return (c1 % self.p2 * self.q2rq2 + c2 % self.q2 * self.p2rp2) % self.n2 #算法改进，反而更慢，不能一下子mod太大

    #cao的
    def fhe_cao_encryt(self, m):
        return (((m % self.p2 + self.r1p2) % self.n2 + self.r3 * self.n1) % self.t,
                ((m % self.q2 + self.r2q2) % self.n2 + self.r4 * self.n1) % self.t)

    def fhe_cao_decryt(self, c1, c2):
        return ((c1 % self.n1) % self.p2 * self.q2rq2 + (c2 % self.n1) % self.q2 * self.p2rp2) % self.n2  # 这个解密更快
        # return (c1 % self.p2 * self.q2rq2 + c2 % self.q2 * self.p2rp2) % self.n2 #算法改进，反而更慢，不能一下子mod太大

    # wo的n元一次运算模型
    def fhe_privacy_one(self, c1, c2, a, b):
        total_c1 = b
        total_c2 = b
        for i in range(len(a)):
            totalc_1 += a[i] * c1[i]
            totalc_2 += a[i] * c2[i]

        return self.fhe_decryt(total_c1, total_c2)
    # wo的n元二次运算模型
    def fhe_privacy_mul(self, c1, c2, a, b, c): #a是二次项的系数矩阵 b是一次项系数 c是常数项系数
        total_c1 = c
        total_c2 = c
        for i in range(len(b)):
            totalc_1 += b[i] * c1[i]
            totalc_2 += b[i] * c2[i]
        for i in range(len(a)):
            for j in range(len(a[i])):
                total_c1 += a[i][j] * c1[i] * c1[j]
                total_c2 += a[i][j] * c2[i] * c2[j]
        return self.fhe_decryt(total_c1, total_c2)


    # 全同态性能测试
    #cao的
    def cao_hom_test(self, len1, len2,lambdas1, lambdas2):
        # 全同态模型测试
        self.fhe_cao_get_key(len1, len2, lambdas1, lambdas2)
        m1 = cryptos.getRandomNumber(self.len1)
        m2 = cryptos.getRandomNumber(self.len1)
        c11, c12 = self.fhe_cao_encryt(m1)
        c21, c22 = self.fhe_cao_encryt(m2)
        # 单
        if (m1 + m2) % self.n2 == self.fhe_cao_decryt(c11 + c21, c12 + c22):
            print('cao满足加法同态')
        else:
            print('cao不满足加法同态')

        if (m1 * m2) % self.n2 == self.fhe_cao_decryt((c11 * c21) % self.t, (c12 * c22) % self.t):
            print('cao满足乘法同态')
        else:
            print('cao不满足乘法同态')
        # 全
        totalc1 = (3 * c11 * c11 * c11 * c11 % self.t + 4 * c11 * c21 * c21 % self.t + 2 * c21 * c21 % self.t) % self.t
        totalc2 = (3 * c12 * c12 * c12 * c12 % self.t + 4 * c12 * c22 * c22 % self.t + 2 * c22 * c22 % self.t) % self.t

        start_t = time.time()
        privacycal = self.fhe_cao_decryt(totalc1, totalc2)
        end_t = time.time()
        print('明文运算是: ', (3 * m1 * m1 * m1 * m1 + 4 * m1 * m2 * m2 + 2 * m2 * m2) % self.n2)
        print('密文解密是: ', privacycal)
        print('解密时间: ', end_t - start_t)

        if (3 * m1 * m1 * m1 * m1 + 4 * m1 * m2 * m2 + 2 * m2 * m2) % self.n2 - privacycal == 0:
            print("cao满足3x^4+4xy^2+2y^2全同态")
        else:
            print("cao不满足3x^4+4xy^2+2y^2全同态")
    #wo的
    def my_hom_test(self, len1, len2, lambdas1, lambdas2):
        # 全同态模型测试
        self.fhe_get_key(len1, len2, lambdas1, lambdas2)
        m1 = cryptos.getRandomNumber(self.len1)
        m2 = cryptos.getRandomNumber(self.len1)
        c11, c12 = self.fhe_encryt(m1)
        c21, c22 = self.fhe_encryt(m2)
        # 单
        if (m1 + m2) % self.n2 == self.fhe_decryt(c11 + c21, c12 + c22):
            print('wo满足加法同态')
        else:
            print('wo不满足加法同态')

        if (m1 * m2) % self.n2 == self.fhe_decryt((c11 * c21) % self.t, (c12 * c22) % self.t):
            print('wo满足乘法同态')
        else:
            print('wo不满足乘法同态')
        # 全
        totalc1 = (3 * c11 * c11 * c11 * c11 % self.t + 4 * c11 * c21 * c21 % self.t + 2 * c21 * c21 % self.t) % self.t
        totalc2 = (3 * c12 * c12 * c12 * c12 % self.t + 4 * c12 * c22 * c22 % self.t + 2 * c22 * c22 % self.t) % self.t

        start_t = time.time()
        privacycal = self.fhe_decryt(totalc1, totalc2)
        end_t = time.time()
        print('明文运算是: ', (3 * m1 * m1 * m1 * m1 + 4 * m1 * m2 * m2 + 2 * m2 * m2) % self.n2)
        print('密文解密是: ', privacycal)
        print('解密时间: ', end_t - start_t)

        # print('密文解密是: ', self.fhe_privacy_one(c1_arrays, c2_arrays, a))
        if (3 * m1 * m1 * m1 * m1 + 4 * m1 * m2 * m2 + 2 * m2 * m2) % self.n2 - privacycal == 0: # self.fhe_privacy_calculate(c11, c12, c21, c22)
            print("wo满足3x^4+4xy^2+2y^2全同态")
        else:
            print("wo不满足3x^4+4xy^2+2y^2全同态")

    # Fhe全套一次加解密测试
    def Fhe_Cao(self, mm, len1, len2, l1, l2):
        # 密钥初始化,可能会很慢
        # self.len1 = len1
        # self.len2 = len2
        # self.lambdas1 = l1
        # self.lambdas2 = l2
        # print("密钥生成")
        self.n1, self.n2, self.t, self.p1, self.q1, self.p2, self.q2, self.s1, self.rp2, self.rq2, self.r1, self.r2, self.r3, self.r4 = self.fhe_get_key(len1, len2, l1, l2)
        flagm = binascii.hexlify(mm.encode('ascii')).decode('utf-8')
        # print('明文是:', mm)
        # mm: int = int(flagm, 16)  # 16转10
        mm = int(flagm, 16)
        # print('明文是:', mm)

        # fhe开始求解
        start_time_enc = time.time()
        c1, c2 = self.fhe_cao_encryt(mm)
        end_time_enc = time.time()
        self.enc_time = end_time_enc - start_time_enc
        # print('密文是:', c1, c2)

        start_time_dec = time.time()
        plaintext = self.fhe_cao_decryt(c1, c2)
        end_time_dec = time.time()
        self.dec_time = end_time_dec - start_time_dec
        # print('解密明文是:', plaintext)
        # print('解密明文是:', n2s(plaintext))
        #
        # print('fhe一轮加密耗时为:', self.enc_time)
        # print('fhe一轮解密耗时为:', self.dec_time)

        # start_time = time.time()
        # self.my_hom_test(512,256,256)
        # end_time = time.time()
        # print('fhe整个计算过程耗时为:', end_time - start_time)

    def Fhe(self, mm, len1, len2, l1, l2):
        # 密钥初始化,可能会很慢
        # self.len1 = len1
        # self.len2 = len2
        # self.lambdas1 = l1
        # self.lambdas2 = l2
        # print("密钥生成")
        self.n1, self.n2, self.t, self.p1, self.q1, self.p2, self.q2, self.s1, self.rp2, self.rq2, self.r1, self.r2, self.r3, self.r4 = self.fhe_get_key(len1, len2, l1, l2)
        flagm = binascii.hexlify(mm.encode('ascii')).decode('utf-8')
        # print('明文是:', mm)
        # mm: int = int(flagm, 16)  # 16转10
        mm = int(flagm, 16)
        # print('明文是:', mm)

        # fhe开始求解
        start_time_enc = time.time()
        c1, c2 = self.fhe_encryt(mm)
        end_time_enc = time.time()
        self.enc_time = end_time_enc - start_time_enc
        # print('密文是:', c1, c2)

        start_time_dec = time.time()
        plaintext = self.fhe_decryt(c1, c2)
        end_time_dec = time.time()
        self.dec_time = end_time_dec - start_time_dec
        # print('解密明文是:', plaintext)
        # print('解密明文是:', n2s(plaintext))
        #
        # print('fhe一轮加密耗时为:', self.enc_time)
        # print('fhe一轮解密耗时为:', self.dec_time)

        # start_time = time.time()
        # self.my_hom_test(512,256,256)
        # end_time = time.time()
        # print('fhe整个计算过程耗时为:', end_time - start_time)


class RSA_Crypto:
    len = 0
    e = 65537
    d = 0
    p = 0
    q = 0
    n = 0
    fai = 0
    enc_time = 0
    dec_time = 0

    def gcd(self, a, b):
        if (b == 0):
            return a
        return self.gcd(b, a % b)

    def myExtGCD(self, a, b):
        if (b == 0):
            return 1, 0, a
        x, y, gcd = self.myExtGCD(b, a % b)
        return y, x - a // b * y, gcd

    def get_key(self):
        self.p = cryptos.getPrime(self.len)
        self.q = cryptos.getPrime(self.len)
        self.n = self.p * self.q
        fai = (self.p - 1) * (self.q - 1)
        while self.gcd(self.e, self.fai) != 1:
            self.p = cryptos.getPrime(self.len)
            self.q = cryptos.getPrime(self.len)
            self.n = self.p * self.q
            self.fai = (self.p - 1) * (self.q - 1)
        self.d = self.myExtGCD(self.fai, self.e)[1] % self.fai
        return self.d, self.n, self.fai

    def encryt(self, m):  # 16进制运算
        # m = binascii.hexlify(m.encode('ascii')).decode('utf-8')
        # m = int(m, 16)
        # print('明文是:',m)
        return gmpy2.powmod(m, self.e, self.n)

    def decryt(self, c):  # 16进制运算
        return gmpy2.powmod(c, self.d, self.n)

    def Rsa(self, m, len, e):
        # 密钥初始化,可能会很慢
        self.len = len
        self.e = e
        self.d, self.n, self.fai = self.get_key()
        self.e = gmpy2.mpz(self.e)
        self.d = gmpy2.mpz(self.d)
        self.n = gmpy2.mpz(self.n)
        self.fai = gmpy2.mpz(self.fai)
        # print('公钥是:', self.e, '和', self.n)
        # print('私钥是:', self.d)
        # 开始求解

        # print('明文是:', m)
        m = gmpy2.mpz(s2n(m))
        start_time_enc = time.time()
        c = self.encryt(m)
        end_time_enc = time.time()

        self.enc_time = end_time_enc - start_time_enc
        # print('密文是:', c)

        start_time_dec = time.time()
        m = self.decryt(c)
        end_time_dec = time.time()
        self.dec_time = end_time_dec - start_time_dec
        # print('解密明文是:', n2s(int(m)))
        #
        # print('rsa一轮加密耗时为:', self.enc_time)
        # print('rsa一轮解密耗时为:', self.dec_time)


class Paillier_Cyrpto:
    len = 0
    g = 0
    n = 0
    nn = 0
    r = 0
    lamda = 0
    p = 0
    q = 0
    v = 0

    def gcd(self, a, b):
        if (b == 0):
            return a
        return self.gcd(b, a % b)

    def findModReverse(self, a, m):  # 扩展欧几里得算法求模逆 ax=1mod m
        a = int(a)
        if self.gcd(a, m) != 1 and self.gcd(a, m) != -1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m

    def fhe_myExtGCD(self, a, b):
        """
        a: 模的取值
        b: 想求逆的值
        """
        # if self.gcd(a, b) != 1 and self.gcd(a, b) != -1:
        #     return None
        if (b == 0):
            return 1, 0, a
        x, y, gcd = self.fhe_myExtGCD(b, a % b)
        return y, x - a // b * y, gcd

    def lcm(self, a, b):
        return a // self.gcd(a, b) * b

    def powmod(self, a, b, c):
        a = a % c
        ans = 1
        b = int(b)
        while b != 0:
            if int(b) & 1:
                ans = (ans * a) % c
            b >>= 1
            a = (a * a) % c
        return ans

    def paillier_encryption(self, m):  # 加密运算
        m = gmpy2.mpz(m)
        # return self.powmod(self.g, m, self.nn) * self.powmod(self.r, self.n, self.nn) % self.nn
        return gmpy2.powmod(self.g, m, self.nn) * gmpy2.powmod(self.r, self.n, self.nn) % self.nn

    def paillier_decryption(self, c):
        return gmpy2.div(gmpy2.sub(gmpy2.powmod(c, self.lamda, self.nn), 1), self.n) * self.u % self.n

    def key_generation(self, len):
        self.len = len
        self.p = getPrime(self.len)
        self.q = getPrime(self.len)
        if self.p == self.q:
            self.q = getPrime(self.len)
        self.n = self.p * self.q
        self.lamda = self.lcm(self.p - 1, self.q - 1)
        # print(lamda)

        while self.gcd(self.n, self.lamda) > 1:
            self.q = getPrime(self.len)
            if self.p == self.q:
                self.q = getPrime(self.len)
            self.n = self.p * self.q
            self.lamda = self.lcm(self.p - 1, self.q - 1)

        self.g = self.n + 1
        self.nn = self.n * self.n
        self.r = cryptos.getRandomNumber(self.len * self.len)
        if self.r > self.n:
            self.r = self.r % self.n
        # 变成大数字
        self.nn = gmpy2.mpz(self.nn)
        self.r = gmpy2.mpz(self.r)
        self.n = gmpy2.mpz(self.n)
        self.p = gmpy2.mpz(self.p)
        self.q = gmpy2.mpz(self.q)
        self.lamda = gmpy2.mpz(self.lamda)

        t = gmpy2.div(gmpy2.sub(gmpy2.powmod(self.g, self.lamda, self.nn), 1), self.n)
        # self.u = self.fhe_myExtGCD(t , self.n ) # 一定互素
        self.u = gmpy2.invert(t, self.n)
        # print(self.g)
        return self.nn, self.n, self.g, self.r, self.lamda, self.u, self.p, self.q

    def Paillier(self, m, lens):
        self.nn, self.n, self.g, self.r, self.lamda, self.u, self.p, self.q = self.key_generation(lens)

        # print("n", n)
        # print("g", g)
        # print("r", r)
        # print("lamda", lamda)
        # print("u", u)
        m = int(s2n(m))

        start_time_enc = time.time()
        c = self.paillier_encryption(m)  # 加密函数
        end_time_enc = time.time()
        self.enc_time = end_time_enc - start_time_enc
        # print('密文是:', c)

        start_time_dec = time.time()
        m = int(self.paillier_decryption(c))  # 解密函数
        end_time_dec = time.time()
        self.dec_time = end_time_dec - start_time_dec
        # print('解密明文是:', n2s(int(m)))
        #
        # print('paillier一轮加密耗时为:', self.enc_time)
        # print('paillier一轮解密耗时为:', self.dec_time)


if __name__ == '__main__':
    m = 'flag{this_is_flag}'
    num = 0

    ave_fhe_enc_cao_time = 0
    ave_fhe_enc_time = 0
    ave_rsa_enc_time = 0
    ave_paillier_enc_time = 0

    ave_fhe_dec_cao_time = 0
    ave_fhe_dec_time = 0
    ave_rsa_dec_time = 0
    ave_paillier_dec_time = 0

    while num < 20:
        num = num + 1
        print('第 ', num, '组')
        caofhe = FHE_Cyrpto()
        caofhe.Fhe_Cao(m, 1024, 512, 96, 64)  # 因为 mod 一个 256*5的数字
        ave_fhe_enc_cao_time += caofhe.enc_time
        ave_fhe_dec_cao_time += caofhe.dec_time

        fhe = FHE_Cyrpto()
        fhe.Fhe(m, 1024, 512, 96, 64)  # 因为 mod 一个 256*5的数字
        ave_fhe_enc_time += fhe.enc_time
        ave_fhe_dec_time += fhe.dec_time

        rsa = RSA_Crypto()
        rsa.Rsa(m, 1024, 17)  # 因为 mod 一个 512*2的数字
        ave_rsa_enc_time += rsa.enc_time
        ave_rsa_dec_time += rsa.dec_time


        paillier = Paillier_Cyrpto()
        paillier.Paillier(m, 1024)  # 因为 mod 一个 512*4的数字
        ave_paillier_enc_time += paillier.enc_time
        ave_paillier_dec_time += paillier.dec_time

        # print (binascii.unhexlify(hex(s2n(m))[2:]) ) # self.test

        print("caofhe : fhe : rsa : paillier一轮加密时间比为 ", 1,fhe.enc_time / caofhe.enc_time, rsa.enc_time / caofhe.enc_time, paillier.enc_time / caofhe.enc_time)
        print("caofhe : fhe : rsa : paillier一轮解密时间比为 ", 1, fhe.dec_time / caofhe.dec_time,rsa.dec_time / caofhe.dec_time, paillier.dec_time / caofhe.dec_time)



    ave_fhe_enc_cao_time /= num
    ave_fhe_enc_time /= num
    ave_rsa_enc_time /= num
    ave_paillier_enc_time /= num

    ave_fhe_dec_cao_time /= num
    ave_fhe_dec_time /= num
    ave_rsa_dec_time /= num
    ave_paillier_dec_time /= num

    print("20轮加密时间均比为 ")
    print("caofhe : fhe : rsa : paillie 20轮加密时间比为 ", 1, ave_fhe_enc_time/ ave_fhe_enc_cao_time, ave_rsa_enc_time/ ave_fhe_enc_cao_time, ave_paillier_enc_time / ave_fhe_enc_cao_time)
    print("caofhe : fhe : rsa : paillie 20轮解密时间比为 ", 1, ave_fhe_dec_time/ ave_fhe_dec_cao_time, ave_rsa_dec_time/ ave_fhe_dec_cao_time, ave_paillier_dec_time / ave_fhe_dec_cao_time)


    # 老板和我的方法解密对比
    fhe = FHE_Cyrpto()
    while num <= 20:
        num = num + 1
        print('第 ', num, '组')
        fhe.cao_hom_test(256, 128, 96, 64)
        fhe.my_hom_test(256, 128, 96, 64)



