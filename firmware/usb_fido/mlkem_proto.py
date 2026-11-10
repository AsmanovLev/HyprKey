import hashlib
from cryptography.hazmat.primitives.asymmetric import mlkem

q = 3329

def bitrev7(n):
    return int(f"{n:07b}"[::-1], 2)

zetas = [pow(17, bitrev7(i), q) for i in range(128)]

def ntt(r):
    # FIPS 203 Algorithm 8
    f = list(r)
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = zetas[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * f[j + length]) % q
                f[j + length] = (f[j] - t) % q
                f[j] = (f[j] + t) % q
        length //= 2
    return f

def ntt_inv(r):
    # FIPS 203 Algorithm 9
    f = list(r)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = zetas[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = (zeta * (f[j + length] - t)) % q
        length *= 2
    for j in range(256):
        f[j] = (f[j] * 3303) % q
    return f

# Test NTT <-> NTT_inv
orig = [(i * 13 + 7) % q for i in range(256)]
ntted = ntt(orig)
inv = ntt_inv(ntted)
assert orig == inv, "NTT roundtrip failed!"
print("NTT roundtrip OK!")

def polymul_naive(a, b):
    # naive multiplication mod X^256 + 1
    c = [0] * 256
    for i in range(256):
        for j in range(256):
            deg = i + j
            prod = (a[i] * b[j]) % q
            if deg < 256:
                c[deg] = (c[deg] + prod) % q
            else:
                c[deg - 256] = (c[deg - 256] - prod) % q
    return c

def basecase_mul(a0, a1, b0, b1, gamma):
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1

def multiply_ntts(a_hat, b_hat):
    c_hat = [0] * 256
    for i in range(64):
        gamma = zetas[64 + i]
        c_hat[4*i], c_hat[4*i+1] = basecase_mul(
            a_hat[4*i], a_hat[4*i+1], b_hat[4*i], b_hat[4*i+1], gamma
        )
        c_hat[4*i+2], c_hat[4*i+3] = basecase_mul(
            a_hat[4*i+2], a_hat[4*i+3], b_hat[4*i+2], b_hat[4*i+3], -gamma % q
        )
    return c_hat

a = [(i * 7 + 1) % q for i in range(256)]
b = [(i * 11 + 5) % q for i in range(256)]

c_naive = polymul_naive(a, b)
c_ntt = ntt_inv(multiply_ntts(ntt(a), ntt(b)))

assert c_naive == c_ntt, "Polynomial multiplication mismatch!"
print("Polynomial multiplication via NTT verified!")

def sample_ntt(stream):
    coeffs = []
    idx = 0
    while len(coeffs) < 256:
        b0 = stream[idx]
        b1 = stream[idx+1]
        b2 = stream[idx+2]
        idx += 3
        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 < q:
            coeffs.append(d1)
        if d2 < q and len(coeffs) < 256:
            coeffs.append(d2)
    return coeffs

def sample_cbd2(buf):
    coeffs = []
    for i in range(32):
        # 4 bytes
        b = buf[4*i : 4*i+4]
        t = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)
        d = (t & 0x55555555) + ((t >> 1) & 0x55555555)
        for j in range(8):
            a = (d >> (4*j)) & 0x3
            b_ = (d >> (4*j + 2)) & 0x3
            coeffs.append((a - b_) % q)
    return coeffs

def prf_eta(sigma, N, eta=2):
    # SHAKE256(sigma || N, 64 * eta = 128)
    h = hashlib.shake_256()
    h.update(sigma + bytes([N]))
    return h.digest(64 * eta)

def xof(rho, x, y):
    h = hashlib.shake_128()
    h.update(rho + bytes([x, y]))
    return h.digest(1024) # enough for 256 coeffs

def byte_encode12(f):
    out = bytearray(384)
    for i in range(128):
        t0 = f[2*i]
        t1 = f[2*i + 1]
        out[3*i + 0] = t0 & 0xFF
        out[3*i + 1] = ((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4)
        out[3*i + 2] = (t1 >> 4) & 0xFF
    return bytes(out)

# Now let's run K-PKE.KeyGen for ML-KEM-768
seed = bytes([42]*64)
d = seed[:32]
z = seed[32:]

g = hashlib.sha3_512(d + b'\x03').digest()
rho = g[:32]
sigma = g[32:]

k_val = 3
s = []
for i in range(k_val):
    s.append(sample_cbd2(prf_eta(sigma, i)))

e = []
for i in range(k_val):
    e.append(sample_cbd2(prf_eta(sigma, k_val + i)))

s_hat = [ntt(s[i]) for i in range(k_val)]
e_hat = [ntt(e[i]) for i in range(k_val)]

# Try both orderings for A_hat: (i, j) vs (j, i)
for order in [("i,j", lambda i,j: (i,j)), ("j,i", lambda i,j: (j,i))]:
    name, get_coords = order
    A_hat = []
    for i in range(k_val):
        row = []
        for j in range(k_val):
            c1, c2 = get_coords(i, j)
            row.append(sample_ntt(xof(rho, c1, c2)))
        A_hat.append(row)
    
    # t_hat = A_hat * s_hat + e_hat
    t_hat = []
    for i in range(k_val):
        poly_acc = [0] * 256
        for j in range(k_val):
            prod = multiply_ntts(A_hat[i][j], s_hat[j])
            poly_acc = [(poly_acc[p] + prod[p]) % q for p in range(256)]
        t_hat_i = [(poly_acc[p] + e_hat[i][p]) % q for p in range(256)]
        t_hat.append(t_hat_i)
    
    pk_candidate = bytearray()
    for i in range(k_val):
        pk_candidate.extend(byte_encode12(t_hat[i]))
    pk_candidate.extend(rho)
    
    # Compare with cryptography
    sk_ref = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    pk_ref = sk_ref.public_key().public_bytes_raw()
    
    if pk_candidate == pk_ref:
        print(f"SUCCESS! Matrix ordering is: {name}")
        break
    else:
        print(f"Mismatch for ordering {name}. Candidate pk[:16]: {pk_candidate[:16].hex()}, Ref pk[:16]: {pk_ref[:16].hex()}")

def byte_decode12(data):
    coeffs = []
    for i in range(128):
        b0 = data[3*i]
        b1 = data[3*i+1]
        b2 = data[3*i+2]
        coeffs.append(b0 | ((b1 & 0x0F) << 8))
        coeffs.append((b1 >> 4) | (b2 << 4))
    return coeffs

def compress(x, d):
    # round((2^d / q) * x) % 2^d
    return ((x * (1 << d) + (q // 2)) // q) % (1 << d)

def decompress(y, d):
    # round((q / 2^d) * y)
    return (y * q + (1 << (d - 1))) >> d

def byte_encode_du(coeffs, d_u=10):
    # Pack 10-bit coeffs: 4 coeffs = 40 bits = 5 bytes
    out = bytearray()
    for i in range(0, len(coeffs), 4):
        c0 = coeffs[i]
        c1 = coeffs[i+1]
        c2 = coeffs[i+2]
        c3 = coeffs[i+3]
        out.append(c0 & 0xFF)
        out.append(((c0 >> 8) & 0x03) | ((c1 & 0x3F) << 2))
        out.append(((c1 >> 6) & 0x0F) | ((c2 & 0x0F) << 4))
        out.append(((c2 >> 4) & 0x3F) | ((c3 & 0x03) << 6))
        out.append((c3 >> 2) & 0xFF)
    return bytes(out)

def byte_decode_du(data, d_u=10):
    coeffs = []
    for i in range(0, len(data), 5):
        b0, b1, b2, b3, b4 = data[i:i+5]
        c0 = b0 | ((b1 & 0x03) << 8)
        c1 = (b1 >> 2) | ((b2 & 0x0F) << 6)
        c2 = (b2 >> 4) | ((b3 & 0x3F) << 4)
        c3 = (b3 >> 6) | (b4 << 2)
        coeffs.extend([c0, c1, c2, c3])
    return coeffs

def byte_encode_dv(coeffs, d_v=4):
    # Pack 4-bit coeffs: 2 coeffs = 1 byte
    out = bytearray()
    for i in range(0, len(coeffs), 2):
        c0 = coeffs[i] & 0x0F
        c1 = coeffs[i+1] & 0x0F
        out.append(c0 | (c1 << 4))
    return bytes(out)

def byte_decode_dv(data, d_v=4):
    coeffs = []
    for b in data:
        coeffs.append(b & 0x0F)
        coeffs.append((b >> 4) & 0x0F)
    return coeffs

def kpke_encrypt(pk, m, r, k_val=3, d_u=10, d_v=4):
    # Decode pk
    t_hat = []
    for i in range(k_val):
        t_hat.append(byte_decode12(pk[384*i : 384*(i+1)]))
    rho = pk[384*k_val : 384*k_val + 32]
    
    # A_hat^T[i][j] = SampleNTT(XOF(rho, i, j))
    A_hat_T = []
    for i in range(k_val):
        row = []
        for j in range(k_val):
            row.append(sample_ntt(xof(rho, i, j)))
        A_hat_T.append(row)
    
    # Sample y, e1, e2
    y = [sample_cbd2(prf_eta(r, i)) for i in range(k_val)]
    e1 = [sample_cbd2(prf_eta(r, k_val + i)) for i in range(k_val)]
    e2 = sample_cbd2(prf_eta(r, 2 * k_val))
    
    y_hat = [ntt(y[i]) for i in range(k_val)]
    
    # u = NTT^-1(A_hat^T * y_hat) + e1
    u = []
    for i in range(k_val):
        poly_acc = [0] * 256
        for j in range(k_val):
            prod = multiply_ntts(A_hat_T[i][j], y_hat[j])
            poly_acc = [(poly_acc[p] + prod[p]) % q for p in range(256)]
        u_i = ntt_inv(poly_acc)
        u_i = [(u_i[p] + e1[i][p]) % q for p in range(256)]
        u.append(u_i)
    
    # v = NTT^-1(t_hat^T * y_hat) + e2 + mu
    v_acc = [0] * 256
    for j in range(k_val):
        prod = multiply_ntts(t_hat[j], y_hat[j])
        v_acc = [(v_acc[p] + prod[p]) % q for p in range(256)]
    v = ntt_inv(v_acc)
    
    # mu = Decompress_1(ByteDecode_1(m))
    # Each bit of m: 32 bytes * 8 = 256 bits
    m_bits = []
    for b in m:
        for bit_i in range(8):
            m_bits.append((b >> bit_i) & 1)
    
    mu = [decompress(b, 1) for b in m_bits]
    v = [(v[p] + e2[p] + mu[p]) % q for p in range(256)]
    
    # Compress and encode
    c1 = bytearray()
    for i in range(k_val):
        comp_u = [compress(x, d_u) for x in u[i]]
        c1.extend(byte_encode_du(comp_u, d_u))
    comp_v = [compress(x, d_v) for x in v]
    c2 = byte_encode_dv(comp_v, d_v)
    
    return bytes(c1) + c2

def kpke_decrypt(dk_pke, c, k_val=3, d_u=10, d_v=4):
    s_hat = []
    for i in range(k_val):
        s_hat.append(byte_decode12(dk_pke[384*i : 384*(i+1)]))
    
    # c1 is 32 * d_u * k bytes
    c1_len = 32 * d_u * k_val
    c1 = c[:c1_len]
    c2 = c[c1_len:]
    
    u = []
    bytes_per_poly = 32 * d_u # 320 bytes for d_u=10
    for i in range(k_val):
        comp_u = byte_decode_du(c1[bytes_per_poly*i : bytes_per_poly*(i+1)], d_u)
        u.append([decompress(x, d_u) for x in comp_u])
    
    comp_v = byte_decode_dv(c2, d_v)
    v = [decompress(x, d_v) for x in comp_v]
    
    u_hat = [ntt(u[i]) for i in range(k_val)]
    su_acc = [0] * 256
    for i in range(k_val):
        prod = multiply_ntts(s_hat[i], u_hat[i])
        su_acc = [(su_acc[p] + prod[p]) % q for p in range(256)]
    su = ntt_inv(su_acc)
    
    w = [(v[p] - su[p]) % q for p in range(256)]
    # Compress_1(w) -> 256 bits -> 32 bytes
    m_bits = [compress(w[p], 1) for p in range(256)]
    m = bytearray(32)
    for i in range(32):
        byte_val = 0
        for bit_i in range(8):
            byte_val |= (m_bits[8*i + bit_i] << bit_i)
        m[i] = byte_val
    return bytes(m)

def mlkem_decaps(dk, c, k_val=3, d_u=10, d_v=4):
    dk_pke_len = 384 * k_val
    dk_pke = dk[:dk_pke_len]
    ek = dk[dk_pke_len : dk_pke_len + 384*k_val + 32]
    h = dk[dk_pke_len + 384*k_val + 32 : dk_pke_len + 384*k_val + 64]
    z = dk[dk_pke_len + 384*k_val + 64 : dk_pke_len + 384*k_val + 96]
    
    m_prime = kpke_decrypt(dk_pke, c, k_val, d_u, d_v)
    g = hashlib.sha3_512(m_prime + h).digest()
    k_prime = g[:32]
    r_prime = g[32:]
    
    # implicit rejection key
    h_j = hashlib.shake_256()
    h_j.update(z + c)
    k_bar = h_j.digest(32)
    
    c_prime = kpke_encrypt(ek, m_prime, r_prime, k_val, d_u, d_v)
    if c == c_prime:
        return k_prime
    else:
        return k_bar

# Test decapsulation against cryptography encapsulate!
# Generate full dk:
h_ek = hashlib.sha3_256(pk_ref).digest()
dk_full = bytearray()
for i in range(k_val):
    dk_full.extend(byte_encode12(s_hat[i]))
dk_full.extend(pk_ref)
dk_full.extend(h_ek)
dk_full.extend(z)

# Encapsulate with cryptography
ss_ref, ct_ref = sk_ref.public_key().encapsulate()

# Decapsulate with our function
ss_cand = mlkem_decaps(bytes(dk_full), ct_ref)

print("Cryptography SS: ", ss_ref.hex())
print("Candidate SS:    ", ss_cand.hex())
assert ss_ref == ss_cand, "Decapsulation shared secret mismatch!"
print("ML-KEM-768 DECAPSULATION VERIFIED AGAINST CRYPTOGRAPHY!")

# Test ML-KEM-1024
def byte_encode_du11(coeffs):
    # Pack 11-bit coeffs: 8 coeffs = 88 bits = 11 bytes
    out = bytearray()
    for i in range(0, len(coeffs), 8):
        c = coeffs[i:i+8]
        out.append(c[0] & 0xFF)
        out.append(((c[0] >> 8) & 0x07) | ((c[1] & 0x1F) << 3))
        out.append(((c[1] >> 5) & 0x3F) | ((c[2] & 0x03) << 6))
        out.append((c[2] >> 2) & 0xFF)
        out.append(((c[2] >> 10) & 0x01) | ((c[3] & 0x7F) << 1))
        out.append(((c[3] >> 7) & 0x0F) | ((c[4] & 0x0F) << 4))
        out.append(((c[4] >> 4) & 0x7F) | ((c[5] & 0x01) << 7))
        out.append((c[5] >> 1) & 0xFF)
        out.append(((c[5] >> 9) & 0x03) | ((c[6] & 0x3F) << 2))
        out.append(((c[6] >> 6) & 0x1F) | ((c[7] & 0x07) << 5))
        out.append((c[7] >> 3) & 0xFF)
    return bytes(out)

def byte_decode_du11(data):
    coeffs = []
    for i in range(0, len(data), 11):
        b = data[i:i+11]
        c0 = b[0] | ((b[1] & 0x07) << 8)
        c1 = (b[1] >> 3) | ((b[2] & 0x3F) << 5)
        c2 = (b[2] >> 6) | (b[3] << 2) | ((b[4] & 0x01) << 10)
        c3 = (b[4] >> 1) | ((b[5] & 0x0F) << 7)
        c4 = (b[5] >> 4) | ((b[6] & 0x7F) << 4)
        c5 = (b[6] >> 7) | (b[7] << 1) | ((b[8] & 0x03) << 9)
        c6 = (b[8] >> 2) | ((b[9] & 0x1F) << 6)
        c7 = (b[9] >> 5) | (b[10] << 3)
        coeffs.extend([c0, c1, c2, c3, c4, c5, c6, c7])
    return coeffs

def byte_encode_dv5(coeffs):
    # Pack 5-bit coeffs: 8 coeffs = 40 bits = 5 bytes
    out = bytearray()
    for i in range(0, len(coeffs), 8):
        c = coeffs[i:i+8]
        out.append((c[0] & 0x1F) | ((c[1] & 0x07) << 5))
        out.append(((c[1] >> 3) & 0x03) | ((c[2] & 0x1F) << 2) | ((c[3] & 0x01) << 7))
        out.append(((c[3] >> 1) & 0x0F) | ((c[4] & 0x0F) << 4))
        out.append(((c[4] >> 4) & 0x01) | ((c[5] & 0x1F) << 1) | ((c[6] & 0x03) << 6))
        out.append(((c[6] >> 2) & 0x07) | ((c[7] & 0x1F) << 3))
    return bytes(out)

def byte_decode_dv5(data):
    coeffs = []
    for i in range(0, len(data), 5):
        b = data[i:i+5]
        c0 = b[0] & 0x1F
        c1 = (b[0] >> 5) | ((b[1] & 0x03) << 3)
        c2 = (b[1] >> 2) & 0x1F
        c3 = (b[1] >> 7) | ((b[2] & 0x0F) << 1)
        c4 = (b[2] >> 4) | ((b[3] & 0x01) << 4)
        c5 = (b[3] >> 1) & 0x1F
        c6 = (b[3] >> 6) | ((b[4] & 0x07) << 2)
        c7 = (b[4] >> 3) & 0x1F
        coeffs.extend([c0, c1, c2, c3, c4, c5, c6, c7])
    return coeffs

# Test encode/decode roundtrip
test_c = [(i * 37) & 0x7FF for i in range(256)]
assert byte_decode_du11(byte_encode_du11(test_c)) == test_c
test_v = [(i * 19) & 0x1F for i in range(256)]
assert byte_decode_dv5(byte_encode_dv5(test_v)) == test_v
print("11-bit and 5-bit packing verified!")

# Now verify ML-KEM-1024 with cryptography!
sk1024_ref = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)
pk1024_ref = sk1024_ref.public_key().public_bytes_raw()

# Generate candidate pk1024:
k_val = 4
g = hashlib.sha3_512(d + b'\x04').digest()
rho = g[:32]
sigma = g[32:]

s = [sample_cbd2(prf_eta(sigma, i)) for i in range(k_val)]
e = [sample_cbd2(prf_eta(sigma, k_val + i)) for i in range(k_val)]
s_hat = [ntt(s[i]) for i in range(k_val)]
e_hat = [ntt(e[i]) for i in range(k_val)]

A_hat = []
for i in range(k_val):
    row = []
    for j in range(k_val):
        row.append(sample_ntt(xof(rho, j, i)))
    A_hat.append(row)

t_hat = []
for i in range(k_val):
    poly_acc = [0] * 256
    for j in range(k_val):
        prod = multiply_ntts(A_hat[i][j], s_hat[j])
        poly_acc = [(poly_acc[p] + prod[p]) % q for p in range(256)]
    t_hat_i = [(poly_acc[p] + e_hat[i][p]) % q for p in range(256)]
    t_hat.append(t_hat_i)

pk1024_candidate = bytearray()
for i in range(k_val):
    pk1024_candidate.extend(byte_encode12(t_hat[i]))
pk1024_candidate.extend(rho)

assert pk1024_candidate == pk1024_ref, "ML-KEM-1024 PK mismatch!"
print("ML-KEM-1024 PUBLIC KEY VERIFIED AGAINST CRYPTOGRAPHY!")

# Verify ML-KEM-1024 decapsulation
h_ek1024 = hashlib.sha3_256(pk1024_ref).digest()
dk1024_full = bytearray()
for i in range(k_val):
    dk1024_full.extend(byte_encode12(s_hat[i]))
dk1024_full.extend(pk1024_ref)
dk1024_full.extend(h_ek1024)
dk1024_full.extend(z)

def kpke_encrypt1024(pk, m, r):
    k_val = 4
    d_u = 11
    d_v = 5
    t_hat = [byte_decode12(pk[384*i : 384*(i+1)]) for i in range(k_val)]
    rho = pk[384*k_val : 384*k_val + 32]
    
    A_hat_T = []
    for i in range(k_val):
        row = []
        for j in range(k_val):
            row.append(sample_ntt(xof(rho, i, j)))
        A_hat_T.append(row)
    
    y = [sample_cbd2(prf_eta(r, i)) for i in range(k_val)]
    e1 = [sample_cbd2(prf_eta(r, k_val + i)) for i in range(k_val)]
    e2 = sample_cbd2(prf_eta(r, 2 * k_val))
    y_hat = [ntt(y[i]) for i in range(k_val)]
    
    u = []
    for i in range(k_val):
        poly_acc = [0] * 256
        for j in range(k_val):
            prod = multiply_ntts(A_hat_T[i][j], y_hat[j])
            poly_acc = [(poly_acc[p] + prod[p]) % q for p in range(256)]
        u_i = ntt_inv(poly_acc)
        u_i = [(u_i[p] + e1[i][p]) % q for p in range(256)]
        u.append(u_i)
    
    v_acc = [0] * 256
    for j in range(k_val):
        prod = multiply_ntts(t_hat[j], y_hat[j])
        v_acc = [(v_acc[p] + prod[p]) % q for p in range(256)]
    v = ntt_inv(v_acc)
    
    m_bits = []
    for b in m:
        for bit_i in range(8):
            m_bits.append((b >> bit_i) & 1)
    mu = [decompress(b, 1) for b in m_bits]
    v = [(v[p] + e2[p] + mu[p]) % q for p in range(256)]
    
    c1 = bytearray()
    for i in range(k_val):
        comp_u = [compress(x, d_u) for x in u[i]]
        c1.extend(byte_encode_du11(comp_u))
    comp_v = [compress(x, d_v) for x in v]
    c2 = byte_encode_dv5(comp_v)
    return bytes(c1) + c2

def kpke_decrypt1024(dk_pke, c):
    k_val = 4
    d_u = 11
    d_v = 5
    s_hat = [byte_decode12(dk_pke[384*i : 384*(i+1)]) for i in range(k_val)]
    c1_len = 32 * d_u * k_val
    c1 = c[:c1_len]
    c2 = c[c1_len:]
    
    u = []
    bytes_per_poly = 32 * d_u # 352 bytes for d_u=11
    for i in range(k_val):
        comp_u = byte_decode_du11(c1[bytes_per_poly*i : bytes_per_poly*(i+1)])
        u.append([decompress(x, d_u) for x in comp_u])
    
    comp_v = byte_decode_dv5(c2)
    v = [decompress(x, d_v) for x in comp_v]
    
    u_hat = [ntt(u[i]) for i in range(k_val)]
    su_acc = [0] * 256
    for i in range(k_val):
        prod = multiply_ntts(s_hat[i], u_hat[i])
        su_acc = [(su_acc[p] + prod[p]) % q for p in range(256)]
    su = ntt_inv(su_acc)
    
    w = [(v[p] - su[p]) % q for p in range(256)]
    m_bits = [compress(w[p], 1) for p in range(256)]
    m = bytearray(32)
    for i in range(32):
        byte_val = 0
        for bit_i in range(8):
            byte_val |= (m_bits[8*i + bit_i] << bit_i)
        m[i] = byte_val
    return bytes(m)

def mlkem1024_decaps(dk, c):
    k_val = 4
    dk_pke_len = 384 * k_val
    dk_pke = dk[:dk_pke_len]
    ek = dk[dk_pke_len : dk_pke_len + 384*k_val + 32]
    h = dk[dk_pke_len + 384*k_val + 32 : dk_pke_len + 384*k_val + 64]
    z = dk[dk_pke_len + 384*k_val + 64 : dk_pke_len + 384*k_val + 96]
    
    m_prime = kpke_decrypt1024(dk_pke, c)
    g = hashlib.sha3_512(m_prime + h).digest()
    k_prime = g[:32]
    r_prime = g[32:]
    
    h_j = hashlib.shake_256()
    h_j.update(z + c)
    k_bar = h_j.digest(32)
    
    c_prime = kpke_encrypt1024(ek, m_prime, r_prime)
    if c == c_prime:
        return k_prime
    else:
        return k_bar

ss1024_ref, ct1024_ref = sk1024_ref.public_key().encapsulate()
ss1024_cand = mlkem1024_decaps(bytes(dk1024_full), ct1024_ref)

print("Cryptography SS1024: ", ss1024_ref.hex())
print("Candidate SS1024:    ", ss1024_cand.hex())
assert ss1024_ref == ss1024_cand, "ML-KEM-1024 Decapsulation mismatch!"
print("ML-KEM-1024 DECAPSULATION VERIFIED AGAINST CRYPTOGRAPHY!")
