from app.utils.bounded import BoundedStore


def test_lru_eviction_keeps_store_bounded():
    store = BoundedStore(max_items=3)

    for i in range(10):
        store[i] = i

    assert len(store) == 3
    assert store.keys() == [7, 8, 9]


def test_recently_used_keys_survive_eviction():
    store = BoundedStore(max_items=2)
    store["a"] = 1
    store["b"] = 2
    store.get("a")
    store["c"] = 3

    assert "a" in store and "c" in store and "b" not in store


def test_ttl_expiry():
    now = [0.0]
    store = BoundedStore(max_items=10, ttl_seconds=10, clock=lambda: now[0])
    store["x"] = 1

    now[0] = 5
    assert store.get("x") == 1          # sliding: refreshed at t=5

    now[0] = 14
    assert store.get("x") == 1

    now[0] = 30
    assert store.get("x") is None
    assert len(store) == 0


def test_setdefault_pop_and_clear():
    store = BoundedStore()

    assert store.setdefault("k", []) == []
    store["k"].append(1)
    assert store["k"] == [1]
    assert store.pop("k") == [1]
    assert store.pop("k", None) is None

    store["z"] = 1
    store.clear()
    assert len(store) == 0
