#!/usr/bin/env python3
from mailhunt import main

if __name__ == "__main__":
    import sys
    raise SystemExit(main(["timeline"] + sys.argv[1:]))
