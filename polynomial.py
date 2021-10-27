# Polynomial evaluation and Lagrange interpolation
#
# unoptimized

from dumb25519 import Scalar, Point, ScalarVector, PointVector
import dumb25519

# polynomial evaluation poly(x)
#    * coeff: ScalarVector of coefficients
def poly_eval(x: Scalar, coeff: ScalarVector) -> Scalar:
    powers_x = ScalarVector()
    powers_x.append(Scalar(1))
    for i in range(len(coeff) - 1):
        powers_x.append(x * powers_x[i])
    return powers_x ** coeff

# polynomial multiplication
#    * poly_a: ScalarVector of polynomial 'a'
#    * poly_b: ScalarVector of polynomial 'b'
def poly_mul(poly_a: ScalarVector, poly_b: ScalarVector) -> ScalarVector:
    prod = [Scalar(0) for i in range(len(poly_a) + len(poly_b) - 1)]
    for i in range(len(poly_a)):
        for j in range(len(poly_b)):
            prod[i + j] += poly_a[i] * poly_b[j]
    return ScalarVector(prod)

# Lagrange interpolation
#    * coords: list of coordinates (in Scalar)
def lagrange(coords: list) -> ScalarVector:
    poly = ScalarVector([Scalar(0) for i in range(len(coords))])
    for i in range(len(coords)):
        basis = ScalarVector([Scalar(1)])
        for j in range(len(coords)):
            if j == i:
                continue
            basis = poly_mul(basis, ScalarVector([-coords[j][0], Scalar(1)]))
            basis *= (coords[i][0] - coords[j][0]).invert()
        poly += basis * coords[i][1]
    return poly

if __name__ == '__main__':
    my_points = [(Scalar(-1), dumb25519.random_scalar()),
                (Scalar(0), dumb25519.random_scalar()),
                (Scalar(1), dumb25519.random_scalar())]
    my_coeffs = lagrange(my_points)

    # test
    passed = True
    for i in my_points:
        passed &= (poly_eval(i[0], my_coeffs) == i[1])
    if passed:
        print("The implementation of Langrange interpolation works!")
    else:
        print("There's a problem in the implementation of Langrange interpolation.")