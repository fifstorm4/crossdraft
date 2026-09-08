#!/usr/bin/env python3
"""
Two small fixes CLAASP needs on a current NumPy.

    python3 patch_claasp.py

Both are upstream bugs that only surface on NumPy 2, which tightened the rules
on assigning an out-of-range Python integer into a fixed-width array.  Under
NumPy 1 the value was silently truncated and the code worked by accident.

  1. generic_functions_vectorized_byte.byte_vector_select_all_words masks a
     uint8 array with 0xffff.  The intent is "keep every bit"; 0xff says that
     without overflowing.

Idempotent: running it twice is harmless, and it reports what it changed.
Nothing else in this toolchain depends on it -- only the statistical tests and
`evaluate_vectorized` go through that path.
"""
import os
import re
import sys

FIXES = [
    ("claasp/cipher_modules/generic_functions_vectorized_byte.py",
     "left_byte_mask = 0xffff",
     "left_byte_mask = 0xff  # 0xffff overflows uint8 on NumPy 2",
     "uint8 mask overflow in byte_vector_select_all_words"),
]


def main():
    try:
        import claasp
    except ImportError:
        sys.exit("claasp is not installed")
    # claasp.__path__ already points at the package, so the site-packages
    # root is one level up -- not two.
    root = os.path.dirname(list(claasp.__path__)[0])

    changed = skipped = 0
    for rel, old, new, why in FIXES:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            print(f"  skip  {rel} not found")
            continue
        src = open(path).read()
        if new in src:
            print(f"  ok    already patched: {why}")
            skipped += 1
            continue
        if old not in src:
            print(f"  skip  pattern not found, upstream may have fixed it: "
                  f"{why}")
            skipped += 1
            continue
        open(path, "w").write(src.replace(old, new))
        print(f"  fixed {why}")
        print(f"        {path}")
        changed += 1

    print()
    print(f"{changed} patched, {skipped} already fine")
    if changed:
        print("Re-run any Python process that had claasp imported.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
