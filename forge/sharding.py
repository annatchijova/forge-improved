"""Deterministic scope partitioning for bounded Forge audits."""
from __future__ import annotations

from collections.abc import Iterable


def deterministic_shards(paths: Iterable[str], max_items: int) -> tuple[tuple[str, ...], ...]:
    """Partition paths into stable, non-overlapping shards of bounded size."""
    if max_items < 1:
        raise ValueError("max_items must be positive")
    ordered = tuple(sorted(set(str(path) for path in paths)))
    return tuple(
        tuple(ordered[index:index + max_items])
        for index in range(0, len(ordered), max_items)
    )


def validate_shards(shards: Iterable[Iterable[str]], expected: Iterable[str], max_items: int) -> None:
    """Raise if a shard plan loses, duplicates, or overfills scope."""
    if max_items < 1:
        raise ValueError("max_items must be positive")
    materialized = [tuple(shard) for shard in shards]
    if any(len(shard) > max_items for shard in materialized):
        raise ValueError("shard exceeds max_items")
    flattened = [path for shard in materialized for path in shard]
    if len(flattened) != len(set(flattened)):
        raise ValueError("shard plan contains duplicate paths")
    if set(flattened) != {str(path) for path in expected}:
        raise ValueError("shard plan does not cover the declared scope exactly")
