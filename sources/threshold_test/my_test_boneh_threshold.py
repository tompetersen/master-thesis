import operator
import functools
import number
from nacl.utils import random


def prime_mod_inv(x, p):
    return pow(x, p - 2, p) # Fermats little theorem


def prod(factors):
    return functools.reduce(operator.mul, factors, 1)


def eval_polynom_mod(polynom, x, p):
    evaluated = ((polynom[j] * pow(x, j)) for j in range(0, len(polynom)))
    return sum(evaluated) % p


def build_lagrange_coefficients(partial_ind, p):
    k_tmp = len(partial_ind)

    def x(idx):
        return partial_ind[idx]

    lagrange_coeff = []
    for i in range(0, k_tmp):
        tmp = [(- x(j) * prime_mod_inv(x(i) - x(j), p))  for j in range(0, k_tmp) if not j == i]
        lagrange_coeff.append(prod(tmp) % p) # lambda_i

    return lagrange_coeff


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
        progress_func(' p\n')
    while 1:
        elgamal_q = number.getPrime(bits-1, randfunc)
        elgamal_p = 2*elgamal_q+1
        if number.isPrime(elgamal_p, randfunc=randfunc):
            break


    # Generate generator g
    # See Algorithm 4.80 in Handbook of Applied Cryptography
    # Note that the order of the group is n=p-1=2q, where q is prime
    if progress_func:
        progress_func(' g\n')
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

    return elgamal_p, elgamal_g, elgamal_q


elgamal_p, elgamal_g, elgamal_q = generate(512, random, print)
p = elgamal_p
#g = elgamal_g
q = elgamal_q

#p = 10288893194183368633555879977788450033590468364557438110388755268910024501255658169612671009283564256037269418454539926931259299649012141475115256170026927
#q = 5144446597091684316777939988894225016795234182278719055194377634455012250627829084806335504641782128018634709227269963465629649824506070737557628085013463

# Create generator of subgroup of order q.
#
# Since subgroups can just have the orders 1, 2, q, 2q=p-1 testing is easy.
# https://crypto.stackexchange.com/questions/7983/elgamal-generation-of-g-value
# https://crypto.stackexchange.com/questions/1451/elgamal-multiplicative-cyclic-group-and-key-generation
while True:
    g = number.getRandomRange(2, p-2, random)
    if (pow(g, q, p) == 1 and pow(g, 2, p) != 1):
        break

print('Parameters: ')
print('\tp: ' + str(p))
print('\tq: ' + str(q))
print('\tg: ' + str(g))
# print('g^q: ' + str(pow(g, q, p)))
# print('g^2: ' + str(pow(g, 2, p)))

a = number.getRandomRange(2, q - 2, random)
public = pow(g, a, p)
print('Created secret: ' + str(a))

# ss
k_ss = 3
n_ss = 5

# Build polynom like p(x) = polynom[0] + polynom[1] * x + ... + polynom[k-1] * x^(k-1)
polynom = [a]
coefficients = [number.getRandomRange(1, q - 1, random) for _ in range(0, k_ss - 1)]
polynom.extend(coefficients)

print('\nCreated polynom: ')
for i, c in enumerate(polynom):
    print('\t%d\t%d' % (i, c))

# Build shares
shares = [(i, eval_polynom_mod(polynom, i, q)) for i in range(1, n_ss + 1)] # (xi, polynom(xi)) = (xi, yi)

print('\nCreated shares: ')
for s in shares:
    print('\t%d\t%d' % s)

# Sender: create message
m = 1337 # TODO: make sure m is in group generated by g
k = number.getRandomRange(1, q - 1, random)
g_k = pow(g, k, p) # aka v
g_ak = pow(public, k, p) # aka w
c = (m * g_ak) % p
message = (g_k, c)

print('\nEncrypted message: ')
print('\t(g_ak) = %d' % g_ak)
print('\tg_k = %d\n\tc = %d' % message)

# Restore message
restore_indices = [0,2,4]
restore_shares = [shares[i] for i in restore_indices] # (xi, yi)

# Partial decryptions
partial_indices = [restore_shares[i][0] for i in range(0, k_ss)] # xi
partial_decryptions = [pow(message[0], restore_shares[i][1], p) for i in range(0, k_ss)] # g_k ^ yi

print('\nRestoring message from partial decryptions: ')
for dec in partial_decryptions:
    print('\t%d' % dec)

# Combination
lagrange_coefficients = build_lagrange_coefficients(partial_indices, q)

print('\nBuilt Lagrange coefficients: ')
for i, l in enumerate(lagrange_coefficients):
    print('\t%d\t%d' % (i, l))

tmp = [pow(partial_decryptions[i], lagrange_coefficients[i], p) for i in range(0, k_ss)]
restored_g_ka = prod(tmp) % p
restored_g_minus_ak = prime_mod_inv(restored_g_ka, p)
restored_m = message[1] * restored_g_minus_ak % p

print('\nRestored g_ak = %d' % restored_g_ka)
print('\nRestored: ' + str(restored_m))

# Asserts

assert len(polynom) == k_ss
assert len(shares) == n_ss
assert len(shares[1]) == 2
assert len(message) == 2
assert len(restore_shares) == k_ss
assert len(restore_shares[2]) == 2
assert restore_shares[2][0] == shares[4][0]
assert len(partial_decryptions) == k_ss
assert len(partial_indices) == k_ss
assert partial_indices[2] == shares[4][0]
assert len(lagrange_coefficients) == k_ss
assert restored_g_ka == g_ak
assert m == restored_m