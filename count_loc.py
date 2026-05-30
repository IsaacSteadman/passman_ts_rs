#!/usr/bin/env python3
from os import listdir, getcwd
from os.path import join, isfile, isdir
from typing import List
from subprocess import check_call


def find_files(base: str, paths: List[str]):
    d1 = join(base, *paths) if len(paths) else base
    for f in listdir(d1):
        if f == "node_modules" or "cache" in f.lower() or "dist" in f.lower():
            continue
        if f in [".git", "LICENSE", "target", "bindings"]:
            continue
        if len(paths) == 1 and paths[0] == "passman_crypto" and f == "pkg":
            continue
        p = join(d1, f)
        if isfile(p):
            parts = f.rsplit(".", 1)
            if len(parts) == 2:
                if parts[1] in [
                    "ts",
                    "js",
                    "tsx",
                    "jsx",
                ]:
                    yield ("js", join(*paths, f))
                elif parts[1] == "rs":
                    yield ("rs", join(*paths, f))
                elif parts[1] in ["html", "less", "css"]:
                    yield ("html", join(*paths, f))
        elif isdir(p):
            yield from find_files(base, paths + [f])


if __name__ == "__main__":
    cwd = getcwd()
    js = []
    rs = []
    html = []
    for t, f in find_files(cwd, []):
        if t == "js":
            js.append(f)
        elif t == "rs":
            rs.append(f)
        elif t == "html":
            html.append(f)
    if js:
        check_call(["wc", "-l"] + js, cwd=cwd)
    else:
        print("No JS files found")
    if rs:
        check_call(["wc", "-l"] + rs, cwd=cwd)
    else:
        print("No Rust files found")
    if html:
        check_call(["wc", "-l"] + html, cwd=cwd)
    else:
        print("No HTML files found")
