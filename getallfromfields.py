#!/usr/bin/env python3
from mailhunt import main

if __name__ == "__main__":
    import sys
    raise SystemExit(main(["headers", "-f", "From", "-f", "Reply-To", "-f", "Return-Path", "-f", "Sender"] + sys.argv[1:]))
