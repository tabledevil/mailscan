#!/usr/bin/python3
# -*- coding: utf-8 -*-
import email
import sys
try:
    import chardet
except ImportError:
    chardet = None
import argparse

def fdecode(string):
    if isinstance(string, str):
        text, encoding = email.header.decode_header(string)[0]
        if encoding is None:
            return text
        else:
            return text.decode(encoding)
    if isinstance(string, bytes):
        try:
            return string.decode('utf-8-sig')
        except UnicodeDecodeError:
            pass

        encodings = ['utf-16', 'iso-8859-15']
        if chardet:
            try:
                detection = chardet.detect(string)
                if "encoding" in detection and detection["encoding"] and len(detection["encoding"]) > 2:
                    encodings.insert(0,detection["encoding"])
            except Exception:
                pass

        for encoding in encodings:
            try:
                return string.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                pass

        # Best effort fallback
        return string.decode('utf-8', errors='replace')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='field', nargs='?', action='append', help='Header field to look for')
    parser.add_argument('infile', nargs='+', type=argparse.FileType('rb'))
    args = parser.parse_args()

    target_fields = set(field.lower() for field in args.field if field) if args.field is not None else None

    for file in args.infile:
        print(file.name)
        msg=email.message_from_binary_file(file)
        file.close()

        for (k,v) in msg.items():
            if target_fields is not None and k.lower() not in target_fields:
                continue
            for (string,encoding) in email.header.decode_header(v):
                if encoding != None and not encoding == "unknown-8bit":
                    value=string.decode(encoding)
                else:
                    value=fdecode(string)
                value=' '.join(value.split())
                print("{}: {}".format(k,value.strip()))
