import number
from nacl.utils import random

# https://tools.ietf.org/html/rfc5114#section-3.2
# Additional Diffie-Hellman Groups for Use with IETF Standards
# 2.1.  1024-bit MODP Group with 160-bit Prime Order Subgroup
p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
a = number.getRandomRange(2, p - 2, random)
private = a
public = pow(g, a, p)

# Sender
m = 1337
k = number.getRandomRange(1, p - 1, random)
g_k = pow(g, k, p)
g_ak = pow(public, k, p)
c = (m * g_ak) % p

# Receiver
g_ak_new = pow(g_k, private, p)
g_minus_ak = pow(g_ak_new, p - 2, p) # Fermat's little theorem (because p is prime)
should_be_one = g_ak_new * g_minus_ak % p
m_new = (c * g_minus_ak) % p

print(str(m))