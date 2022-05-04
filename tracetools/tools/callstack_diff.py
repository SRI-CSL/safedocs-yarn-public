#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import sys
from tracetools import parse_log, yarn_args, global_config


def parse_args():
    parser = yarn_args.YarnArgParser('show differences betweeen callstacks',
                                     demangle=True, out=True, ask_binja=True,
                                     skip=True, multiprocess=True)
    parser.add_argument('-f', '--unique_fns', action='store_true',
                        help='print summary of fn calls unique to '
                        'each result')
    p = parser.parse_args()
    return p


class CallStackDiff():
    range_num = 2

    def __init__(self, yarn_args):
        filters = ['CallEntry']
        self.changed = False
        self.range_num = len(yarn_args.results_obj)
        for i in range(self.range_num):
            if i > 0:
                args.output = None
            setattr(self, f'pl{i}',
                    parse_log.MemtraceLog(
                        yarn_args=args, yarn_args_result_idx=i,
                        filters=filters,
                        track_callstack=getattr(self, f'_track_callstack{i}')
                    ))
            setattr(self, f'last_stack{i}', getattr(self, f"pl{i}").stack)
        self.out = self._get_pl(0).print_out

    def _track_callstack0(self, o, binfo):
        self.changed = True

    def _track_callstack1(self, o, binfo):
        self.changed = True

    def _get_pl(self, num):
        return getattr(self, f"pl{num}")

    def _get_last_stack(self, num):
        return getattr(self, f"last_stack{num}")

    def calc_unique(self):
        sets = []
        iter_range = range(self.range_num)
        pls = [self._get_pl(i) for i in iter_range]

        def del_callstack(o):
            o.track_callstack = None
        map(del_callstack, pls)

        for i in iter_range:
            s = set()
            while True:
                try:
                    o = next(self._get_pl(i))
                    if o.call_kind in [o.CALL, o.INDIRECT]:
                        binfo = pls[i].binfo
                        seg = binfo.get_segment_at(o.target_addr)
                        fn = binfo.addr_to_fn(o.target_addr, seg)
                        if fn:
                            n = fn.symbol.full_name if global_config.demangle else fn.name
                            s.add(n)
                except StopIteration:
                    break
            sets.append(s)

        for i in iter_range:
            print("function calls unique to %d (size %d)" % (i, len(sets[i])))
            others = [sets[other] for other in iter_range if not other == i]
            print("{" + ", ".join(sets[i] - set().union(*others)) + "}")

    def run(self):
        iter_res = []
        last_match = True

        def unpause(i):
            paused[i] = False

        done = [False] * self.range_num
        paused = [False] * self.range_num
        iter_range = range(self.range_num)
        out = self.out
        while not all(done):
            if all([p or d for (p, d) in zip(paused, done)]):
                # just in case they all get paused but not done
                paused = [False] * self.range_num

            for i in iter_range:
                if not paused[i] or done[i]:
                    try:
                        next(self._get_pl(i))
                    except StopIteration:
                        done[i] = True
                a = self._get_last_stack(i)
                iter_res.append(a)
            if iter_res and self.changed:
                self.changed = False
                match = all(map(lambda x: x == iter_res[0], iter_res))
                if not match:
                    if len(iter_res[0].stack) > len(iter_res[1].stack):
                        paused[0] = False
                        paused[1] = True
                    elif len(iter_res[0].stack) < len(iter_res[1].stack):
                        paused[0] = True
                        paused[1] = False
                    else:  # unpause all
                        map(lambda i: unpause(i), iter_range)
                    if last_match:
                        print("----", file=out)
                        print("-%d: %s" % (i, iter_res[i]),
                              file=out)
                    last_match = False
                    [print("+%d: %s" % (i, iter_res[i]), file=out)
                     for i in iter_range if not paused[i]]
                else:
                    last_match = True
                    map(lambda i: unpause(i), iter_range)
            iter_res = []

    def close(self):
        for i in range(self.range_num):
            self._get_pl(i).close()


if __name__ == "__main__":
    args = parse_args()
    if len(args.parse_results) != 2:
        print("must specify -R exactly twice")
        sys.exit(1)

    rs = []
    for i in range(len(args.parse_results)):
        print(f"{i}: {args.results_obj[i]}")

    c = CallStackDiff(args)
    if args.unique_fns:
        c.calc_unique()
    else:
        c.run()
    c.close()
