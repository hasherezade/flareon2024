p=0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd
a=0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
b=0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

c_x=0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
c_y=0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182

E = EllipticCurve(GF(p), [a,b])
G = E(c_x, c_y)
n = G.order()
print("Number of bits in n:", n.nbits())

factors = n.factor()
#factors = filter(lambda p, e: (p^e).bit_length() < 35, factors)
factors = list(filter(lambda x: int(x[0]^x[1]).bit_length() < 35, factors))

print("n's factors:", factors)
PRIVATE_KEY_BIT_SIZE = 128
import random
import functools
private_key = random.randrange(2^PRIVATE_KEY_BIT_SIZE)
print(private_key)
print(len(Integer(private_key).bits()))
P = private_key * G
print("We know that the private key is", PRIVATE_KEY_BIT_SIZE, "bits long")
print("Lets find which of the factors of G's order are relevant for finding the private key")
# find factors needed such that the order is greater than the secret key size

count_factors_needed = 0
new_order = 1
for p, e in factors:
    new_order *= p^e
    count_factors_needed += 1
    if new_order.nbits() >= PRIVATE_KEY_BIT_SIZE:
        print("Found enough factors! The rest are not needed")
        break
factors = factors[:count_factors_needed]
print("Considering these factors:", factors)
print("Calculating discrete log for each quotient group...")
subsolutions = []
subgroup = []

for p, e in factors:
    p_pow_e = p^e
    print("p^e=")
    print(p_pow_e)
    quotient_n = (n // p ^ e)
    G0 = quotient_n * G # G0's order is p^e
    P0 = quotient_n * P
    k = G0.discrete_log(P0)
    print("k=")
    print(k)
    subsolutions.append(k)
    subgroup.append(p ^ e) # k the order of G0
    
print("Running CRT...")
found_key = crt(subsolutions, subgroup)
print(len(found_key.bits()))
print("Product:")
product = functools.reduce(operator.mul, subgroup)
print(product)
print("Brutforcing missing bits...")

for m in range(1 << 17):
	#print(m)
	res = found_key + m * product
	#print(res)
	if (res * G == P):
		print("Found!")
		found_key = res
		break
assert found_key * G == P
assert private_key == found_key
print(found_key)
print("success")