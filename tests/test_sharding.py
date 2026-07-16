import pytest

from forge.sharding import deterministic_shards, validate_shards


def test_deterministic_shards_are_sorted_bounded_and_complete():
    paths = ["z.py", "a.py", "m.py", "a.py", "b.py"]
    shards = deterministic_shards(paths, 2)
    assert shards == (("a.py", "b.py"), ("m.py", "z.py"))
    validate_shards(shards, paths, 2)


def test_sharding_is_reproducible_for_different_input_order():
    assert deterministic_shards(["b.py", "a.py", "c.py"], 2) == deterministic_shards(["c.py", "b.py", "a.py"], 2)


def test_sharding_rejects_invalid_limits_and_bad_plans():
    with pytest.raises(ValueError, match="positive"):
        deterministic_shards(["a.py"], 0)
    with pytest.raises(ValueError, match="duplicate"):
        validate_shards((("a.py", "a.py"),), ["a.py"], 2)
    with pytest.raises(ValueError, match="exactly"):
        validate_shards((("a.py",),), ["a.py", "b.py"], 2)
