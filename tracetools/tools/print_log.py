#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools import yarn_args, parse_log, log_entries


def parse_args():
    parser = yarn_args.YarnArgParser('Iterate through mem trace log',
                                     skip=True, threads=True)
    parser.add_argument('--filter', '-f', action="append",
                        default=[], help='Filter output to only include \
                        these entry types, by default prints all',
                        choices=[m.__name__ for m in log_entries.entry_kinds])
    parser.add_argument("--bytes", "-b", action="store_true",
                        help="print corresponding WriteLogEntry bytes")
    parser.add_argument('--quiet', '-q', action="store_true",
                        help="Don't print anything.  "
                        "(This is for performance testing.)")
    parser.add_argument("--index", action="store_true",
                        help="print log index")
    p = parser.parse_args()
    return p


if __name__ == "__main__":
    mmap = None
    args = parse_args()
    if not args.filter:
        args.filter = ['EntryObj']
    ml = parse_log.MemtraceLog(yarn_args=args,
                               filters=args.filter)
    if args.quiet:
        for i in ml:
            pass
    elif args.index:
        if args.bytes:
            for i in ml:
                content = f"[{ml.write_entry_log_bytes(i)}]" \
                    if log_entries.is_kind(i, log_entries.FileWriteEntry) \
                       else ""
                print(f"{ml.log_count}:{i}{content}")
        else:
            for i in ml:
                print(f"{ml.log_count}:{i}")
    else:
        if args.bytes:
            for i in ml:
                content = f"[{ml.write_entry_log_bytes(i)}]" \
                    if log_entries.is_kind(i, log_entries.FileWriteEntry) \
                       else ""
                print(f"{i}{content}")
        else:
            for i in ml:
                print(i)

    ml.close()
