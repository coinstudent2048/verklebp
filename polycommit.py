# Polynomial commitment scheme - Modified inner product argument
# Non-interactive through Fiat-Shamir heuristic
# Source: Section 3.1 of ia.cr/2019/1021

import dumb25519

class Prover:
    def __init__(self):
        pass
    # define functions per phase

    # fiat-shamir challenge
    def challenge(prefix, *data) -> Scalar:
        return dumb25519.hash_to_scalar(prefix, *data)

class Verifier:
    def __init__(self):
        pass
    # define function per phase

    def verification(proof) -> bool:
        pass

if __name__ == '__main__':
    # sample run