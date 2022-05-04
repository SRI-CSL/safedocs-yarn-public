# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
# Consts for VersionAddrInfo field names
AddrKind = type("AddrKind", (object,),
                {
                    f.upper(): f
                    for f in
                    ["PCEntry", "CallEntry", "MemEntry", "begin", "end"]
                })


# Consts for VersionAddrInfo subtypes
AddrSubtype = type("AddrSubtype", (object,),
                   {
                       f.upper(): f
                       for f in
                       ["return", "target_addr", "read", "write"]
                   })

# Consts for VersionAddrInfo subtypes
AddrInstype = type("AddrInstype", (object,),
                   {
                       f.upper(): f
                       for f in ["cmp", "mov"]
                   })

# Consts for VersionAddrInfo subtypes
AddrField = type("AddrField", (object,),
                 {
                     f.upper(): f
                     for f in
                     ["pc", "target_addr"]
                 })
