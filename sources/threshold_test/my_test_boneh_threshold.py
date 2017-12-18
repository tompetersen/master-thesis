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


# ElGamal
p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
q = 0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353 # 160 Bit

#elgamal_p, elgamal_g, elgamal_q = generate(512, random, print)
#p = elgamal_p
#g = elgamal_g
#q = elgamal_q

p = 10288893194183368633555879977788450033590468364557438110388755268910024501255658169612671009283564256037269418454539926931259299649012141475115256170026927
q = 5144446597091684316777939988894225016795234182278719055194377634455012250627829084806335504641782128018634709227269963465629649824506070737557628085013463
#g = 4649232162098852178813243496780269353118313910173797022020568242305887008736813643156110480136722727587796588638005087966416653647026856119180268256252479

while True:
    g = number.getRandomRange(2, p-2, random)
    print('Testing ' + str(g))
    if (pow(g, q, p) == 1 and pow(g, 2, p) != 1):
        break

print('p: ' + str(p))
print('q: ' + str(q))
print('g: ' + str(g))
print('g^q: ' + str(pow(g, q, p)))
print('g^2: ' + str(pow(g, 2, p)))

# ss
k_ss = 3
n_ss = 5

# a = number.getRandomRange(2, p - 2, random)
a = number.getRandomRange(2, q - 2, random)
public = pow(g, a, p)

# Build polynom like p(x) = polynom[0] + polynom[1] * x + ... + polynom[k-1] * x^(k-1)
polynom = [a]
coefficients = [number.getRandomRange(1, q - 1, random) for _ in range(0, k_ss - 1)]
polynom.extend(coefficients)

# Build shares
shares = [(i, eval_polynom_mod(polynom, i, q)) for i in range(1, n_ss + 1)] # (xi, polynom(xi)) = (xi, yi)

# Sender: create message
m = 1337
#k = number.getRandomRange(1, p - 1, random)
k = number.getRandomRange(1, q - 1, random)
g_k = pow(g, k, p) # aka v
g_ak = pow(public, k, p) # aka w
c = (m * g_ak) % p
message = (g_k, c)

# Restore message
restore_indices = [0,2,4]
restore_shares = [shares[i] for i in restore_indices] # (xi, yi)

# Partial decryptions
partial_indices = [restore_shares[i][0] for i in range(0, k_ss)] # xi
partial_decryptions = [pow(message[0], restore_shares[i][1], p) for i in range(0, k_ss)] # g_k ^ yi

# Combination
lagrange_coefficients = build_lagrange_coefficients(partial_indices, q)

tmp = [pow(partial_decryptions[i], lagrange_coefficients[i], p) for i in range(0, k_ss)]
restored_g_ka = prod(tmp) % p
restored_g_minus_ak = prime_mod_inv(restored_g_ka, p) # Fermat's little theorem (because p is prime)
restored_m = message[1] * restored_g_minus_ak % p

print('a: ' + str(a))

# JUST TESTING
restored_a = sum((restore_shares[i][1] * lagrange_coefficients[i]) % p for i in range(0, k_ss)) % p # Removing this % p leads to the same wrong value as restored_g_ka
testing_value = pow(g_k, restored_a, p)
print('Original_g_ka = ' + str(g_ak))
print('restored_g_ka = ' + str(restored_g_ka))
print('testing_value = ' + str(testing_value))

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


# Output

print('p = ' + str(p) + '\n')

print('Created secret: ' + str(a))

print('\nCreated polynom: ')
for i, c in enumerate(polynom):
    print('\t%d\t%d' % (i, c))

print('\nCreated shares: ')
for s in shares:
    print('\t%d\t%d' % s)

print('\nEncrypted message: ')
print('\t(g_ak = %d)' % g_ak)
print('\tg_k = %d\n\tc = %d' % message)

print('\nRestoring message from partial encryptions: ')
for dec in partial_decryptions:
    print('\t%d' % dec)

print('\nBuilt Lagrange coefficients: ')
for i, l in enumerate(lagrange_coefficients):
    print('\t%d\t%d' % (i, l))

# JUST TEMPORARY TESTING
tmp_secret_restored = sum(restore_shares[i][1] * lagrange_coefficients[i] for i in range(0, k_ss)) % p
print('TMP_SECRET_RESTORED = ' + str(tmp_secret_restored))
print('TMP_MESSAGE = ' + str(message[1] * prime_mod_inv(pow(message[0], tmp_secret_restored, p), p) % p))

print('\nRestored g_ak = %d' % restored_g_ka)

print('\nRestored: ' + str(restored_m))