#!/usr/bin/env python3
# Copyright (c) 2026 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.
"""Write seed corpora and dictionaries for the VillageSQL fuzz targets.

Usage: make_seeds.py SOURCE_DIR OUT_DIR

Creates OUT_DIR/villagesql_fuzz_<name>_seed_corpus.zip and
OUT_DIR/villagesql_fuzz_<name>.dict, derived from the source tree where
possible so they track the code.
"""

import glob
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zipfile


def write_corpus(out_dir, fuzzer, seeds):
    path = os.path.join(out_dir, f"villagesql_fuzz_{fuzzer}_seed_corpus.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for seed in seeds:
            if isinstance(seed, str):
                seed = seed.encode()
            z.writestr(hashlib.sha1(seed).hexdigest(), seed)


def write_dict(out_dir, fuzzer, tokens):
    path = os.path.join(out_dir, f"villagesql_fuzz_{fuzzer}.dict")
    with open(path, "w") as f:
        for token in sorted(set(tokens)):
            escaped = "".join(
                c if " " <= c <= "~" and c not in '"\\' else f"\\x{ord(c):02X}"
                for c in token)
            f.write(f'"{escaped}"\n')


# mysqltest commands that are not SQL. Statements starting with these words
# are dropped from the SQL seeds.
MYSQLTEST_WORDS = {
    "let", "echo", "source", "eval", "error", "disable_warnings",
    "enable_warnings", "disable_query_log", "enable_query_log",
    "disable_result_log", "enable_result_log", "connect", "connection",
    "disconnect", "replace_result", "replace_regex", "exec", "perl",
    "if", "while", "dec", "inc", "sleep", "die", "skip", "exit", "end",
    "remove_file", "write_file", "copy_file", "file_exists", "mkdir",
    "rmdir", "sorted_result", "send", "reap", "query_vertical", "vertical_results",
    "horizontal_results", "append_file", "cat_file", "list_files",
    "shutdown_server", "restart", "expect", "assert", "require",
}


def sql_statements(test_file):
    statements = []
    delimiter = ";"
    current = []
    heredoc_end = None
    with open(test_file, errors="replace") as f:
        for line in f:
            stripped = line.strip()
            # Skip the bodies of write_file, append_file and perl blocks.
            if heredoc_end is not None:
                if stripped == heredoc_end:
                    heredoc_end = None
                continue
            match = re.match(r"(?:--)?\s*(write_file|append_file|perl)\b(.*)", stripped)
            if match:
                args = match.group(2).replace(";", " ").split()
                if match.group(1) == "perl":
                    heredoc_end = args[0] if args else "EOF"
                else:
                    heredoc_end = args[1] if len(args) > 1 else "EOF"
                current = []
                continue
            if not stripped or stripped.startswith("#") or stripped.startswith("--"):
                continue
            match = re.match(r"(?i)delimiter\s+(\S+)", stripped)
            if match:
                delimiter = match.group(1)
                current = []
                continue
            current.append(line.rstrip("\n"))
            if stripped.endswith(delimiter):
                text = "\n".join(current).strip()
                text = text[: -len(delimiter)].strip()
                current = []
                first = re.split(r"[\s(;]", text, maxsplit=1)[0].lower()
                if text and first not in MYSQLTEST_WORDS and "$" not in text:
                    statements.append(text)
    return statements


def sql_seeds(src):
    seeds = set()
    pattern = os.path.join(src, "mysql-test", "suite", "villagesql", "**", "*.test")
    for test_file in sorted(glob.glob(pattern, recursive=True)):
        seeds.update(sql_statements(test_file))
    return sorted(seeds)[:20000]


def sql_dict(src):
    tokens = set()
    with open(os.path.join(src, "sql", "lex.h")) as f:
        tokens.update(re.findall(r'SYM(?:_FN|_HK)?\("([A-Z0-9_]+)"', f.read()))
    tokens.update(["(", ")", ",", ";", ".", "'", "`", "@@", "/*!", "*/"])
    return tokens


def semver_seeds():
    bases = ["mysql-8.4", "mysql-9.7", "percona-8.4", "percona-9.7"]
    seeds = []
    for base in bases:
        seeds += [f"{base}_0.0.7", f"{base}_1.2.3-alpha.1+build.5",
                  f"{base}_10.100.1000-rc.0\n{base}_10.100.1000"]
    seeds += ["0.0.4-dev", "1.0.0\nmysql-8.4_1.0.0",
              "mysql-8.4_1.0.0-1\nmysql-8.4_1.0.0-alpha"]
    return seeds


def make_tar(members, compression=""):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w" + (":" + compression if compression else "")) as tar:
        for name, kind, value in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = value.encode()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value
                tar.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = value
                tar.addfile(info)
    return buf.getvalue()


def veb_seeds():
    manifest = json.dumps({"name": "fuzz", "version": "1.0.0"})
    base = [("manifest.json", "file", manifest), ("lib", "dir", None),
            ("lib/fuzz.so", "file", "\x7fELF")]
    return [
        make_tar(base),
        make_tar(base, "gz"),
        make_tar(base, "xz"),
        make_tar(base + [("lib/alias.so", "symlink", "fuzz.so")]),
        make_tar(base + [("lib/up", "symlink", "../manifest.json")]),
        make_tar(base + [("lib/hard.so", "hardlink", "lib/fuzz.so")]),
        make_tar(base + [("a/b/c/d.txt", "file", "nested")]),
        make_tar([("manifest.json", "file", "{\"name\": \"fuzz\"}")]),
        make_tar([("manifest.json", "file", "[]")]),
    ]


def clone_seeds():
    def payload(extensions):
        return json.dumps({"format": 1, "server_version": "mysql-8.4_0.0.7",
                           "schema_version": "mysql-8.4_0.0.7",
                           "extensions": extensions})
    ext = {"name": "vsql_fuzz", "version": "1.0.0", "veb_sha256": "0" * 64}
    return [
        payload([ext]),
        payload([dict(ext, version="")]),
        payload([dict(ext, name="missing")]),
        payload([ext, dict(ext, name="other", version="2.0.0")]),
        payload([]),
    ]


JSON_TOKENS = ["{", "}", "[", "]", ":", ",", "\"", "true", "false", "null",
               "\"name\"", "\"version\"", "\"veb_sha256\"", "\"extensions\"",
               "\"format\"", "\"server_version\"", "\"schema_version\"",
               "\"vsql_fuzz\"", "\"1.0.0\"", "\"fuzz\""]


def main():
    src, out = sys.argv[1], sys.argv[2]
    write_corpus(out, "sql_parse", sql_seeds(src))
    write_dict(out, "sql_parse", sql_dict(src))
    write_corpus(out, "semver", semver_seeds())
    write_dict(out, "semver", ["mysql-8.4_", "mysql-9.7_", "percona-8.4_",
                               "percona-9.7_", ".", "-", "+", "\n"])
    write_corpus(out, "veb", veb_seeds())
    write_dict(out, "veb", JSON_TOKENS + ["manifest.json", "lib/", "../", "/"])
    write_corpus(out, "clone_payload", clone_seeds())
    write_dict(out, "clone_payload", JSON_TOKENS + ["../", "/"])


if __name__ == "__main__":
    main()
