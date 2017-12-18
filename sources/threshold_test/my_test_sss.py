import operator
import functools

import number
from nacl.utils import random


p = number.getPrime(1024, random)
k = 3
n = 5
secret = 1337

# Build polynom like p(x) = polynom[0] + polynom[1] * x + ... + polynom[k-1] * x^(k-1)
polynom = [secret]
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
print('Created shares: ')
for (x,y) in shares:
    print('\t%d %d' % (x, y))

# Restore secret
restore_indices = [0,2,4]
restore_shares = [shares[i] for i in restore_indices]

def prime_mod_inv(x, p):
    return pow(x, p - 2, p) # Fermats little theorem

def prod(factors):
    return functools.reduce(operator.mul, factors, 1)

def interpolate_polynom(shares, p):
    k = len(shares)
    x = lambda idx: shares[idx][0]
    y = lambda idx: shares[idx][1]

    lagrange_coefficients = []
    for i in range(0, k):
        tmp = [(-x(j) * prime_mod_inv(x(i) - x(j), p)) for j in range(0, k) if not j == i]
        lagrange_coefficients.append(prod(tmp) % p)

    return sum(lagrange_coefficients[i] * y(i) for i in range(0, k)) % p

print('Restoring secret from shares: ')
for (x,y) in restore_shares:
    print('\t%d %d' % (x, y))
restored_secret = interpolate_polynom(restore_shares, p)
print('Restored: ' + str(restored_secret))