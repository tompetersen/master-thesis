import operator
import functools
import number
from nacl.utils import random

# ElGamal
p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
a = number.getRandomRange(2, p - 2, random)
public = pow(g, a, p)
# ss
k = 3
n = 5

# Build polynom like p(x) = polynom[0] + polynom[1] * x + ... + polynom[k-1] * x^(k-1)
polynom = [a]
coefficients = [number.getRandomRange(1, p - 1, random) for _ in range(0, k - 1)]
polynom.extend(coefficients)

print('Created polynom: ')
for i, c in enumerate(polynom):
    print('\t%d %d' % (i, c))

# Build shares
def eval_polynom_mod(polynom, x, p):
    evaluated = ((polynom[i] * pow(x, i)) for i in range(0, len(polynom)))
    return sum(evaluated) % p

shares = [(i, eval_polynom_mod(polynom, i, p)) for i in range(1, n + 1)] # shares = (x, polynom(x))
print('\nCreated shares: ')
for s in shares:
    print('\t%d %d' % s)

# Sender: create message
m = 1337
k = number.getRandomRange(1, p - 1, random)
g_k = pow(g, k, p)
g_ak = pow(public, k, p)
c = (m * g_ak) % p
message = (g_k, c)
print('\nEncrypted message: ')
print('\t(g_ak = %d)' % g_ak)
print('\tg_k = %d\n\tc = %d' % message)

# Restore message
restore_indices = [0,2,4]
restore_shares = [shares[i] for i in restore_indices]
partial_decryptions = [(share[0], pow(message[0], share[1], p)) for share in restore_shares]

def prime_mod_inv(x, p):
    return pow(x, p - 2, p) # Fermats little theorem

def prod(factors):
    return functools.reduce(operator.mul, factors, 1)

def build_lagrange_coefficients(partial_encryptions, p):
    k = len(partial_encryptions)
    x = lambda idx: partial_encryptions[idx][0]

    lagrange_coefficients = []
    for i in range(0, k):
        tmp = [(-x(j) * prime_mod_inv(x(i) - x(j), p)) % p for j in range(0, k) if not j == i]
        lagrange_coefficients.append(prod(tmp)) # lambda_i

    return lagrange_coefficients

print('\nRestoring message from partial encryptions: ')
for enc in partial_decryptions:
    print('\t%d %d' % enc)

lagrange_coefficients = build_lagrange_coefficients(partial_decryptions, p)
print('\nBuilt Lagrange coefficients: ')
for l in lagrange_coefficients:
    print('\t' + str(l))

restored_g_ka = prod(pow(partial_decryptions[i][1], lagrange_coefficients[i], p) for i in range(0, len(partial_decryptions))) % p

print('Restored g_ak = %d' % restored_g_ka)
restored_g_minus_ak = pow(restored_g_ka, p - 2, p) # Fermat's little theorem (because p is prime)
restored_m = message[1] * restored_g_minus_ak % p
print('\nRestored: ' + str(restored_m))
