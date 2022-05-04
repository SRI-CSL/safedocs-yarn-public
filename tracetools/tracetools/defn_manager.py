# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import json
import dataclasses
from typing import Dict, get_args
import glob
import logging
import os


class JsonHelper():
    @classmethod
    def from_dict(cls, d: dict):
        new_d = {}
        for f in dataclasses.fields(cls):
            args = get_args(f.type)

            if len(args) > 1 and not args[1] == str:
                new_d[f.name] = {}
                for (k, v) in d.get(f.name, {}).items():
                    v["_name"] = k
                    subobj = args[1].from_dict(v)
                    new_d[f.name][subobj._name] = subobj
            else:
                if f.name in d:
                    new_d[f.name] = d.get(f.name)
        return cls(**new_d)


@dataclasses.dataclass
class BinPathInfo(JsonHelper):
    _name: str
    path: str
    timeout: int = None
    environ: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class VersionInfo(JsonHelper):
    _name: str
    root_dir: str
    src: str = ""
    bins: Dict[str, BinPathInfo] = dataclasses.field(default_factory=dict)
    environ: Dict[str, str] = dataclasses.field(default_factory=dict)
    timeout: int = None

    def get_bin_path_info(self, bin_name: str) -> BinPathInfo:
        return self.bins.get(bin_name, None)

    def default_bin(self):
        return list(self.bins.keys())[0]


@dataclasses.dataclass
class BinArgs(JsonHelper):
    _name: str
    parser_args: str = "{in_file}"
    delete: str = dataclasses.field(default_factory=list)
    copy: str = dataclasses.field(default_factory=list)
    trace_socket: bool = False
    trace_file: bool = True
    timeout: int = None
    is_parser: bool = True
    background: bool = False
    setup_script: str = ""
    environ: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ParserInfo(JsonHelper):
    name: str
    versions: Dict[str, VersionInfo]
    bins: Dict[str, BinArgs]
    input_type: str = "pdf"
    timeout: int = 90
    environ: Dict[str, str] = dataclasses.field(default_factory=dict)
    schema_version: str = ""

    def get_timeout(self, parser_version: str, bin_name: str) -> int:
        v = self.get_version(parser_version)
        bpinfo = v.get_bin_path_info(bin_name)
        b = self.get_bin_args(bin_name)
        # bininfo overrides global, version overrides bininfo,
        # binpathinfo overrides version
        timeout = b.timeout if b and b.timeout is not None else self.timeout
        timeout = v.timeout if v and v.timeout is not None else timeout
        timeout = bpinfo.timeout if bpinfo.timeout is not None else timeout
        return timeout

    def get_environ(self, parser_version: str, bin_name: str,
                    in_file: str) -> Dict[str, str]:
        v = self.get_version(parser_version)
        bpinfo = v.get_bin_path_info(bin_name)
        b = self.get_bin_args(bin_name)
        # bininfo overrides global, version overrides bininfo,
        # binpathinfo overrides version
        environ = dict(self.environ)
        if b:
            environ.update(b.environ)
        if v:
            environ.update(v.environ)
        if bpinfo:
            environ.update(bpinfo.environ)
        for (k, val) in environ.items():
            environ[k] = val.format(**{"root_dir": v.root_dir,
                                       "in_file": in_file})
        return environ

    def get_version(self, parser_version):
        return self.versions.get(parser_version, None)

    def get_bin_args(self, bin_name: str) -> BinArgs:
        return self.bins.get(bin_name, None)

    def default_version(self):
        return list(self.versions.keys())[0]


class DefnLoader():
    def __init__(self, path: str):
        self.defs = {}
        for p in glob.glob(os.path.join(path, "*.json")):
            with open(p, "r") as f:
                try:
                    i = ParserInfo.from_dict(json.load(f))
                except json.decoder.JSONDecodeError as e:
                    logging.error(f"JSON parsing error found in {p}")
                    raise e

                self.defs[i.name] = i

    def print_supported_parsers(self, input_type=None):
        for d in self.defs.values():
            if input_type is not None and d.input_type != input_type:
                continue
            info_str = f"Parser family {d.name}:\n"
            info_str += f"\t input type: {d.input_type}:"
            for v in d.versions.values():
                if not v.bins or not os.path.exists(v.root_dir):
                    continue
                version_str = f"\t version: {v._name}\n"
                version_str += "\t\t supported binaries: (name/command)"
                for b in v.bins.values():
                    if b._name not in d.bins:
                        continue
                    args = d.bins[b._name].parser_args
                    if info_str:
                        print(info_str)
                        info_str = None
                    if version_str:
                        print(version_str)
                        version_str = None
                    print(f"\t\t\t - {b._name}: {b.path} {args}")

    def default_parser(self):
        return list(self.defs.keys())[0]
