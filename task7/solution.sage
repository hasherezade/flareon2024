p=0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd
a=0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
b=0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

# Generator coordinates:
G_x=0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
G_y=0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182

#server coordinates:
s_x=0xb3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06
s_y=0x85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb
# Server Private: 153712271226962757897869155910488792420

#client coordinates:
k_x=0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499
k_y=0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15
# Client Private: 168606034648973740214207039875253762473

ec = EllipticCurve(GF(p), [0,0,0,a,b])
#pt_s = ec([s_x, s_y])
pt_s = ec([k_x, k_y])

G = ec([G_x, G_y])
n = G.order()
print("Number of bits in n:", n.nbits())

factors = n.factor()
factors = list(filter(lambda x: int(x[0]^x[1]).bit_length() < 35, factors))

print("n's factors:", factors)
PRIVATE_KEY_BIT_SIZE = 128

P = pt_s

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
    quotient_n = (n // p ^ e)
    G0 = quotient_n * G # G0's order is p^e
    P0 = quotient_n * P
    k = G0.discrete_log(P0)
    subsolutions.append(k)
    subgroup.append(p ^ e) # k the order of G0
	
print("Factors:")
print(factors)
print("Subgroup:")
print(subgroup)
print("Running CRT...")

found_key = crt(subsolutions, subgroup)

print("Partial key:", found_key)
print("Len: ", len(found_key.bits()))

product = subgroup[0]
for i in range(1, len(subgroup)):
	product *= subgroup[i]

print("Brutforcing missing bits...")
is_found = False

while True:
	found_key += product
	if (found_key * G == P):
		print("Found!")
		is_found = True
		break

if is_found:
	#assert private_key == found_key
	print("Found key:", found_key)
	print(hex(found_key))
	print("Len: ", len(found_key.bits()))
	print("success")
else:
	print("failed")
