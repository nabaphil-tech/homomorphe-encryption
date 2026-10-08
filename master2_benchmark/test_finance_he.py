from finance_he import dataset

def test_deterministic():
    assert dataset(100, 42) == dataset(100, 42)

def test_signed_values():
    values = dataset(100, 42)
    assert all(isinstance(v, int) for v in values)
    assert min(values) < 0 and max(values) > 0

def test_paillier_sum():
    from finance_he import paillier_sum
    assert paillier_sum([5, -3, 12], 2048)["result"] == 14

def test_bfv_sum():
    from finance_he import bfv_sum
    assert bfv_sum([5, -3, 12])["result"] == 14

def test_bfv_polynomial():
    from finance_he import bfv_polynomial
    assert bfv_polynomial(12, 7)["result"] == 136
