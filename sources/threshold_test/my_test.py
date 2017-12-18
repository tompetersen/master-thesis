import datetime

from nacl.utils import random
import number

# Generate an ElGamal key with N bits
# https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py
def generate(bits, randfunc, progress_func=None):
    """Randomly generate a fresh, new ElGamal key.
    The key will be safe for use for both encryption and signature
    (although it should be used for **only one** purpose).
    :Parameters:
        bits : int
            Key length, or size (in bits) of the modulus *p*.
            Recommended value is 2048.
        randfunc : callable
            Random number generation function; it should accept
            a single integer N and return a string of random data
            N bytes long.
        progress_func : callable
            Optional function that will be called with a short string
            containing the key parameter currently being generated;
            it's useful for interactive applications where a user is
            waiting for a key to be generated.
    :attention: You should always use a cryptographically secure random number generator,
        such as the one defined in the ``Crypto.Random`` module; **don't** just use the
        current time and the ``random`` module.
    :Return: An ElGamal key object (`ElGamalobj`).
    """

    # Generate a safe prime p
    # See Algorithm 4.86 in Handbook of Applied Cryptography
    if progress_func:
        progress_func(str(datetime.datetime.now().time()) + ' p\n')
    while 1:
        elgamal_q = number.getPrime(bits-1, randfunc)
        elgamal_p = 2*elgamal_q+1
        if number.isPrime(elgamal_p, randfunc=randfunc):
            break


    # Generate generator g
    # See Algorithm 4.80 in Handbook of Applied Cryptography
    # Note that the order of the group is n=p-1=2q, where q is prime
    if progress_func:
        progress_func(str(datetime.datetime.now().time()) + ' g\n')
    while 1:
        # We must avoid g=2 because of Bleichenbacher's attack described
        # in "Generating ElGamal signatures without knowning the secret key",
        # 1996
        #
        elgamal_g = number.getRandomRange(3, elgamal_p, randfunc)
        safe = 1
        if pow(elgamal_g, 2, elgamal_p) == 1:
            safe = 0
        if safe and pow(elgamal_g, elgamal_q, elgamal_p) == 1:
            safe = 0
        # Discard g if it divides p-1 because of the attack described
        # in Note 11.67 (iii) in HAC
        if safe and divmod(elgamal_p - 1, elgamal_g)[1] == 0:
            safe = 0
        # g^{-1} must not divide p-1 because of Khadir's attack
        # described in "Conditions of the generator for forging ElGamal
        # signature", 2011
        ginv = number.inverse(elgamal_g, elgamal_p)
        if safe and divmod(elgamal_p - 1, ginv)[1] == 0:
            safe = 0
        if safe:
            break

    # Generate private key x
    if progress_func:
        progress_func(str(datetime.datetime.now().time()) + ' x\n')
    elgamal_private = number.getRandomRange(2, elgamal_p - 1, randfunc)

    # Generate public key y
    if progress_func:
        progress_func(str(datetime.datetime.now().time()) + ' y\n')
    elgamal_public = pow(elgamal_g, elgamal_private, elgamal_p)

    return elgamal_p, elgamal_g, elgamal_private, elgamal_public


# while 1:
    # elgamal_p, elgamal_g, elgamal_private, elgamal_public = generate(512, random, print)
