# Polynomial commitment scheme - Modified inner product argument
# Non-interactive through Fiat-Shamir heuristic
# Source: Subsection 3.1 of ia.cr/2019/1021
#
# unoptimized

from dumb25519 import Scalar, Point, ScalarVector, PointVector
from polynomial import powers, poly_eval
import dumb25519

H = dumb25519.hash_to_point('H')

def prove(G_vec: PointVector, P: Point, x: Scalar, v: Scalar, a_vec: ScalarVector, r: Scalar) -> dict:
    dlen = len(a_vec)
    if dlen & (dlen - 1) != 0 or dlen <= 1:   # check if not power of two
        raise ValueError('length of polynomial not a power of 2 or less than 2')

    # build statement and P_prm
    b_vec = powers(x, dlen - 1)
    statement = [P, x, v, G_vec]
    U = dumb25519.hash_to_point('U Fiat-Shamir hash', *statement)
    P_prm = P + v * U

    # build L and R (index j is reversed)
    L_vec = PointVector()
    R_vec = PointVector()
    l_vec = ScalarVector()
    r_vec = ScalarVector()
    u_vec = ScalarVector()
    splt = dlen   # vector splitter (the lo & hi subscripts from paper)
    G_prm = G_vec
    a_prm = a_vec
    b_prm = b_vec
    while splt > 1:
        splt //= 2   # split in half evenly
        l_j = dumb25519.random_scalar()   # blinding factor
        r_j = dumb25519.random_scalar()   # blinding factor
        L_j = a_prm[:splt] ** G_prm[splt:] + l_j * H + (a_prm[:splt] ** b_prm[splt:]) * U
        R_j = a_prm[splt:] ** G_prm[:splt] + r_j * H + (a_prm[splt:] ** b_prm[:splt]) * U
        l_vec.append(l_j)
        r_vec.append(r_j)
        L_vec.append(L_j)
        R_vec.append(R_j)
        u_j = dumb25519.hash_to_scalar('LR Fiat-Shamir hash', *statement, L_j, R_j)
        u_vec.append(u_j)
        a_prm = a_prm[splt:] * u_j.invert() + a_prm[:splt] * u_j
        b_prm = b_prm[:splt] * u_j.invert() + b_prm[splt:] * u_j
        G_prm = G_prm[:splt] * u_j.invert() + G_prm[splt:] * u_j

    # zero knowledge opening (Equation 2 from paper)
    u_vec_sqrd = u_vec * u_vec
    r_prm = l_vec ** u_vec_sqrd + r + r_vec ** u_vec_sqrd.invert()
    Q = a_prm[0] * (G_prm[0] + b_prm[0] * U) + r_prm * H
    d = dumb25519.random_scalar()   # blinding factor
    s = dumb25519.random_scalar()   # blinding factor
    R = d * (G_prm[0] + b_prm[0] * U) + s * H
    c = dumb25519.hash_to_scalar('ZKopen Fiat-Shamir hash', Q, R)
    z1 = a_prm[0] * c + d
    z2 = c * r_prm + s
    zkopen = [R, z1, z2]

    return {'state': statement, 'L': L_vec, 'R': R_vec, 'zkopen': zkopen}

def verify(proof: dict) -> bool:
    # build u_vec (index j is reversed)
    L_vec = proof['L']
    R_vec = proof['R']
    u_vec = ScalarVector()
    for (L_j, R_j) in zip(L_vec, R_vec):
        u_j = dumb25519.hash_to_scalar('LR Fiat-Shamir hash', *proof['state'], L_j, R_j)
        u_vec.append(u_j)

    # build s_vec (be careful on indices), G, and b
    # this is slow, hence this is the reason behind the 'amortization strategy'
    # (Subsection 3.2 from paper), but we will not implement it here
    G_vec = proof['state'][3]
    dlen = len(G_vec)
    b_vec = powers(proof['state'][1], dlen - 1)
    s_vec = ScalarVector()
    for i in range(dlen):
        bin = i
        prod = Scalar(1)
        for j in range(len(u_vec) - 1, -1, -1):   # reverse
            bit = bin & 1
            if bit == 1:
                prod *= u_vec[j]
            else:
                prod *= u_vec[j].invert()
            bin >>= 1
        s_vec.append(prod)
    G = s_vec ** G_vec
    b = s_vec ** b_vec

    # build P_prm and Q
    U = dumb25519.hash_to_point('U Fiat-Shamir hash', *proof['state'])
    P_prm = proof['state'][0] + proof['state'][2] * U
    u_vec_sqrd = u_vec * u_vec
    Q = L_vec ** u_vec_sqrd + P_prm + R_vec ** u_vec_sqrd.invert()

    # verify zero knowledge opening
    R = proof['zkopen'][0]
    c = dumb25519.hash_to_scalar('ZKopen Fiat-Shamir hash', Q, R)
    z1 = proof['zkopen'][1]
    z2 = proof['zkopen'][2]
    return c * Q + R == z1 * (G + b  * U) + z2 * H

if __name__ == '__main__':
    # build proving relation ((P, x, v); (a_vec, r)) and G_vec
    x = dumb25519.random_scalar()
    a_vec = ScalarVector([dumb25519.random_scalar() for i in range(4)])   # polynomial coefficients
    v = poly_eval(x, a_vec)
    G_vec = PointVector([dumb25519.random_point() for i in range(len(a_vec))])
    r = dumb25519.random_scalar()   # blinding factor
    P = a_vec ** G_vec + r * H   # the actual commitment

    # test 1 (should work)
    print('Test 1: start prover')
    transcript = prove(G_vec, P, x, v, a_vec, r)
    print('Test 1: start verifier')
    if verify(transcript):
        print('Verified!')
    else:
        print('Something\'s wrong :(')

    # test 2 (should NOT work)
    print('Test 2: start prover')
    transcript = prove(G_vec, P, x + Scalar(1), v, a_vec, r)   # wrong x
    print('Test 2: start verifier')
    if verify(transcript):
        print('Something\'s wrong :(')
    else:
        print('Prover you\'re desperate!')

    # test 3 (should NOT work)
    print('Test 3: start prover')
    transcript = prove(G_vec, P, x, v + Scalar(1), a_vec, r)   # wrong v
    print('Test 3: start verifier')
    if verify(transcript):
        print('Something\'s wrong :(')
    else:
        print('Prover you\'re desperate!')

    # test 4 (should NOT work)
    a_vec[1] += Scalar(1)
    print('Test 4: start prover')
    transcript = prove(G_vec, P, x, v, a_vec, r)   # wrong a_vec
    print('Test 4: start verifier')
    if verify(transcript):
        print('Something\'s wrong :(')
    else:
        print('Prover you\'re desperate!')