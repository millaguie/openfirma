#!/usr/bin/env python3
"""Reject workflow YAML with duplicate keys.

GitHub Actions refuses a workflow whose mapping repeats a key — a job's
`permissions` written twice, two `on:` blocks — and the failure arrives as a run
that ends in zero seconds, which reads like an infrastructure hiccup rather than
a syntax error. PyYAML's default loader silently accepts the duplicate with
last-key-wins, so `python3 -c "yaml.safe_load(...)"` calling a broken file valid
is exactly the hole this closes (round two's N-5 repair, `90d1854`).

Run from the repository root; exits 1 naming every file and key repetition.
"""

import glob
import sys

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


UniqueKeyLoader.construct_mapping = construct_mapping

failed = 0
for path in sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")):
    try:
        with open(path, encoding="utf-8") as handle:
            yaml.load(handle, Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        print(f"{path}: {error}", file=sys.stderr)
        failed += 1
    else:
        print(f"ok, {path}")

if failed:
    sys.exit(1)
