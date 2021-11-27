# Polynomial commitment scheme - Modified inner product argument
# Non-interactive through Fiat-Shamir heuristic
# Source: Section 3.1 of ia.cr/2019/1021
#
# unoptimized

from dumb25519 import Scalar, Point, ScalarVector, PointVector
import dumb25519
from polynomial import poly_eval

H = dumb25519.hash_to_point('H')

def prove(x: Scalar, a_vec: ScalarVector) -> dict:
    d = len(a_vec)
    if d & (d - 1) != 0 or d <= 0:   # check if not power of two
        raise ValueError('length of polynomial not a power of 2')

    # build statement
    v, b_vec = poly_eval(x, a_vec)
    G_vec = PointVector()
    for i in range(len(a_vec)):
        G_vec.append(dumb25519.random_point())
    r = dumb25519.random_scalar()   # blinding factor
    P = a_vec ** G_vec + r * H
    statement = [P, x, v, G_vec]   # mentioned again in return
    
    U = dumb25519.random_point()   # "hopefully" has unknown DL relationship to G_vec and H
    P_prm = P + v * U
    
    # build 'L' and 'R' (index j is reversed)

    return {'state': statement, 'L': None, 'R': None, 'zkopen': None}

def verify(proof: dict) -> bool:
    pass

if __name__ == '__main__':
    pass