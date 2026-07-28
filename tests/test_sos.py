"""Sum-of-squares certificate tests."""

from certkit import verify_sos
from certkit.sos import SOS_SCHEMA


def poly(**terms):
    """Helper: poly(**{"2,0": (1,1)}) -> {"2,0": [1,1]}."""
    return {k: [v[0], v[1]] for k, v in terms.items()}


def cert(target, squares, scale=1):
    return {"schema": SOS_SCHEMA, "scale": scale, "target": target, "squares": squares}


def test_x_squared_is_a_square():
    # target = x^2, certificate: 1 * x^2 == (x)^2
    target = {"2,0": [1, 1]}
    squares = [{"1,0": [1, 1]}]
    assert verify_sos(cert(target, squares))


def test_perfect_square_trinomial():
    # x^2 + 2xy + y^2 == (x + y)^2
    target = {"2,0": [1, 1], "1,1": [2, 1], "0,2": [1, 1]}
    squares = [{"1,0": [1, 1], "0,1": [1, 1]}]
    assert verify_sos(cert(target, squares))


def test_sum_of_two_squares():
    # x^2 + y^2 == (x)^2 + (y)^2
    target = {"2,0": [1, 1], "0,2": [1, 1]}
    squares = [{"1,0": [1, 1]}, {"0,1": [1, 1]}]
    assert verify_sos(cert(target, squares))


def test_positive_scale_factor():
    # 2 * (x^2) == (x)^2 + (x)^2
    target = {"2,0": [1, 1]}
    squares = [{"1,0": [1, 1]}, {"1,0": [1, 1]}]
    assert verify_sos(cert(target, squares, scale=2))


def test_rational_coefficients():
    # 4 * (1/4 x^2) == (x)^2
    target = {"2,0": [1, 4]}
    squares = [{"1,0": [1, 1]}]
    assert verify_sos(cert(target, squares, scale=4))


# --------------------------------------------------------------------------- #
# rejections
# --------------------------------------------------------------------------- #


def test_perturbed_certificate_rejected():
    # target perturbed by one coefficient: identity no longer holds exactly.
    target = {"2,0": [1, 1], "1,1": [3, 1], "0,2": [1, 1]}  # 3xy, not 2xy
    squares = [{"1,0": [1, 1], "0,1": [1, 1]}]
    assert not verify_sos(cert(target, squares))


def test_negative_scale_rejected():
    target = {"2,0": [1, 1]}
    squares = [{"1,0": [1, 1]}]
    assert not verify_sos(cert(target, squares, scale=-1))


def test_zero_scale_rejected():
    target = {"2,0": [1, 1]}
    squares = [{"1,0": [1, 1]}]
    assert not verify_sos(cert(target, squares, scale=0))


def test_empty_square_list_rejected():
    assert not verify_sos(cert({"2,0": [1, 1]}, []))


def test_zero_polynomial_square_rejected():
    # An all-zero square would let a certificate pad its list for free.
    assert not verify_sos(cert({"2,0": [1, 1]}, [{"1,0": [1, 1]}, {}]))


def test_wrong_schema_rejected():
    c = cert({"2,0": [1, 1]}, [{"1,0": [1, 1]}])
    c["schema"] = "other/v1"
    assert not verify_sos(c)


def test_malformed_input_returns_false_not_raises():
    for bad in [
        None,
        {},
        {"schema": SOS_SCHEMA},
        {"schema": SOS_SCHEMA, "scale": "x", "target": {}, "squares": [{}]},
        {"schema": SOS_SCHEMA, "scale": 1, "target": {"bad": [1, 1]}, "squares": [{"1,0": [1, 1]}]},
    ]:
        assert verify_sos(bad) is False


def test_negative_target_is_not_certifiable():
    # -x^2 is never a sum of squares; no certificate should pass.
    target = {"2,0": [-1, 1]}
    squares = [{"1,0": [1, 1]}]
    assert not verify_sos(cert(target, squares))
