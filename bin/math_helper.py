import random
from primesieve import *

lowPrimes = n_primes(6553)

def rabinMiller(num):
    # Returns True if num is a prime number.
    s = num - 1
    t = 0
    while s % 2 == 0:
        # keep halving s while it is even (and use t
        # to count how many times we halve s)
        s = s // 2
        t += 1
    for trials in range(5): # try to falsify num's primality 5 times
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1: # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

def isPrime(num):
    # Return True if num is a prime number. This function does a quicker
    # prime number check before calling rabinMiller().

    if (num < 2):
        return False # 0, 1, and negative numbers are not prime

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabinMiller(), but unlike rabinMiller() is not guaranteed to
    # prove that a number is prime.

    # See if any of the low prime numbers can divide num
    for prime in lowPrimes:
        if (num % prime == 0):
            #print prime
            return False

    if  pow(2, num-1, num) != 1:
        return False

    # If all else fails, call rabinMiller() to determine if num is a prime.
    return rabinMiller(num)

def egcd(a, b):
    aa,bb=a,b
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q

        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y
