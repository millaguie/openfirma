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
import re
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
workflows = {}
for path in sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")):
    try:
        with open(path, encoding="utf-8") as handle:
            loaded = yaml.load(handle, Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        print(f"{path}: {error}", file=sys.stderr)
        failed += 1
    else:
        workflows[path] = loaded
        print(f"ok, {path}")


def release_notes_match_the_matrix(release):
    """The release body's GUI list is derived from the one place that decides it.

    Round 3's N3-1: the publish step said aarch64 Windows shipped the window while
    its matrix entry carried no `gui: true`, and the notes had just started reaching
    the release page. Comparing the two texts turns that sentence into something the
    lint job checks on every push instead of something a reviewer has to catch.
    """
    matrix = release["jobs"]["build"]["strategy"]["matrix"]["include"]
    gui = sorted(entry["target"] for entry in matrix if entry.get("gui"))
    runs = [
        step.get("run", "")
        for step in release["jobs"]["publish"]["steps"]
        if "Ships inside the artifacts for" in step.get("run", "")
    ]
    # Option B publishes no window at all: an empty matrix list needs no notes
    # sentence, and a notes sentence naming nobody is equally consistent.
    if not gui and not runs:
        return None
    if len(runs) != 1:
        return "the publish job must state the GUI list once"
    if not gui:
        return "the matrix builds no GUI but the notes still list one"
    text = runs[0]
    start = text.index("Ships inside the artifacts for")
    end = text.index('echo ""', start)
    named = sorted(set(re.findall(r"[a-z0-9_]+(?:-[a-z0-9_]+)+", text[start:end])))
    named = [name for name in named if name in {e["target"] for e in matrix}]
    if sorted(set(named)) != gui:
        return f"notes name {sorted(set(named))}, matrix gui:true is {gui}"
    return None


release_path = ".github/workflows/release.yml"
if release_path in workflows:
    problem = release_notes_match_the_matrix(workflows[release_path])
    if problem:
        print(f"{release_path}: {problem}", file=sys.stderr)
        failed += 1
    else:
        print(f"ok, {release_path}: release notes list matches matrix gui:true")

if failed:
    sys.exit(1)
