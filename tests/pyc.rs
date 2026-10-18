//! The Python bytecode normalizer, checked against add-determinism where it and python3
//! are installed: the same .pyc files, compiled by python3 in varied ways or crafted,
//! normalized by both, must come out the same bytes and file metadata, and still load.
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

const EXE: &str = env!("CARGO_BIN_EXE_debbuild-rs");
/// The reference: add-determinism's binary.
const ADD_DET: &str = "add-det";

/// Skip a test whose tools are missing: a failure under `DEBBUILD_RS_TEST_REQUIRE_TOOLS`.
fn skip(what: &str) {
    assert!(
        std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
        "no {what}"
    );
    eprintln!("skipped: no {what}");
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn tools() -> bool {
    for t in ["python3", ADD_DET] {
        if !have(t) {
            skip(t);
            return false;
        }
    }
    true
}

fn run(cmd: &mut Command) -> Output {
    let o = cmd.output().unwrap();
    assert!(o.status.success(), "{cmd:?}: {o:?}");
    o
}

/// Python sources whose constants repeat across code objects, in ways marshal writes
/// once or more depending on the compiling process.
const SOURCES: &[(&str, &str)] = &[
    (
        "consts.py",
        r#"
"""Module docstring."""
import os
X = "hello"
B = b"bytes" * 2
T = (1, 2, "three", (4.5, -0.0), frozenset({"a", "b"}))
BIG = 123456789012345678901234567890
NEG = -98765432109876543210
F = (0.0, -0.0, float("nan"), float("inf"), 1e300, 3j, 1 + 2j, -0j)

def f(a, b=2, *args, k="hello", **kw):
    """Docstring of f."""
    return a + b, "hello", X, (1, 2, "three"), BIG, frozenset({"a", "b"}), 3j

def g(a, b=2, *args, k="hello", **kw):
    """Docstring of f."""
    return a + b, "hello", X, (1, 2, "three"), BIG, frozenset({"a", "b"}), 3j

class C:
    attr = ("hello", 1, 2)

    def m(self, x):
        return [x for x in range(10) if x in {1, 2, 3}], lambda y: y + "hello"

    def n(self, x):
        return {k: v for k, v in zip("ab", "cd")}, (lambda y: y + "hello")

    @property
    def p(self):
        try:
            return f"{self!r:>10}"
        except (ValueError, TypeError) as e:
            raise RuntimeError("hello") from e

def gen():
    yield from range(3)
    async def inner():
        async with os.fdopen(0) as h:
            await h
    return inner

def result():
    return (f(1)[:5], g(2)[:5], C().m(1)[0], T, BIG + NEG, len(F))
"#,
    ),
    (
        "pkg/__init__.py",
        "from .sub import value\n__all__ = ['value']\n",
    ),
    (
        "pkg/sub.py",
        "def value():\n    return {'a': (1, 2), 'b': (1, 2), 'c': 'a' * 300}\n",
    ),
    ("empty.py", ""),
    (
        "big.py",
        "TUPLE = (\n    'x',\n) * 0 + tuple(range(300))\nT300 = (\n    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',\n) * 1\n",
    ),
];

/// The script writing the compiled corpus into argv[1]: the sources compiled by
/// `py_compile` and `compileall`, as timestamp and hash-based files, optimized, in parallel,
/// and from processes whose objects hold other references when marshal runs.
const COMPILE: &str = r#"
import compileall, importlib.util, marshal, os, py_compile, shutil, subprocess, sys
from importlib._bootstrap_external import _code_to_timestamp_pyc, _code_to_hash_pyc
out = sys.argv[1]
src = os.path.join(out, "src")
def run(*args):
    subprocess.run([sys.executable, *args], check=True, stdout=subprocess.DEVNULL)
for i, mode in enumerate(["TIMESTAMP", "CHECKED_HASH", "UNCHECKED_HASH"]):
    for opt in [0, 1, 2]:
        d = os.path.join(out, "py_compile-%d-%d" % (i, opt))
        os.makedirs(d)
        for name in os.listdir(src):
            p = os.path.join(src, name)
            if p.endswith(".py"):
                py_compile.compile(p, cfile=os.path.join(d, name + "c"), doraise=True, optimize=opt,
                                   invalidation_mode=py_compile.PycInvalidationMode[mode])
for flags, name in [([], "plain"), (["-O"], "O"), (["-OO"], "OO"), ([], "j0")]:
    d = os.path.join(out, "compileall-" + name)
    shutil.copytree(src, d)
    extra = ["-j", "0"] if name == "j0" else []
    run(*flags, "-m", "compileall", "-q", *extra, d)
# the same sources compiled by a process that imported more first
d = os.path.join(out, "busy")
shutil.copytree(src, d)
run("-c", "import json, email.message, collections, typing, compileall, sys; compileall.compile_dir(sys.argv[1], quiet=1)", d)
# code objects whose constants have other references while marshal writes them
d = os.path.join(out, "held")
os.makedirs(d)
for name in os.listdir(src):
    p = os.path.join(src, name)
    if not p.endswith(".py"):
        continue
    co = compile(open(p).read(), p, "exec")
    held = []
    def hold(c):
        for k in c.co_consts:
            held.append(k)
            if hasattr(k, "co_consts"):
                hold(k)
        held.extend(c.co_names)
    hold(co)
    st = os.stat(p)
    with open(os.path.join(d, name + "c"), "wb") as f:
        f.write(_code_to_timestamp_pyc(co, int(st.st_mtime), st.st_size))
    with open(os.path.join(d, name + ".hash.pyc"), "wb") as f:
        f.write(_code_to_hash_pyc(co, b"12345678", True))
"#;

/// The script writing crafted .pyc files into argv[1], for the running Python's magic
/// number and for other versions.
const CRAFT: &str = r#"
import importlib.util, os, struct, sys
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
MAGIC = importlib.util.MAGIC_NUMBER
I = lambda n: struct.pack("<i", n)
F = 0x80
def w(name, body, head=None):
    with open(os.path.join(out, name + ".pyc"), "wb") as f:
        f.write((MAGIC + b"\0" * 12 if head is None else head) + body)
def z(s, c="z", f=0): return bytes([ord(c) | f, len(s)]) + s
def a(s, c="a", f=0): return bytes([ord(c) | f]) + I(len(s)) + s
def st(items, f=0): return bytes([ord(")") | f, len(items)]) + b"".join(items)
def bt(items, f=0): return bytes([ord("(") | f]) + I(len(items)) + b"".join(items)
def r(i): return b"r" + I(i)
def L(n, *d): return b"l" + I(n) + b"".join(struct.pack("<H", x) for x in d)
def g(x): return b"g" + struct.pack("<d", x)
def other(m, size): return struct.pack("<H", m) + b"\r\n" + b"\0" * (size - 4)
w("strings", st([z(b"abc", "z", F), z(b"abc", "Z", F), a(b"abc", "a", F), a(b"abc", "A", F),
                 a(b"abc", "u", F), a(b"abc", "t", F), a(b"abc", "s", F), z(b"abc"), a(b"abc", "u")]))
w("unflagged", st([z(b"abc"), a(b"abc"), z(b"x", "Z")]))
w("numbers", st([g(0.0), g(0.0), g(-0.0), g(-0.0), g(float("nan")), g(float("nan")),
                 b"y" + struct.pack("<dd", 1, 2), b"y" + struct.pack("<dd", 1, 2),
                 b"i" + I(1), b"i" + I(1), L(1, 1), L(1, 1), b"T", b"T"]))
w("longs", st([L(2, 1, 0), L(1, 0x8000), L(2, 0xffff, 1), L(-1, 0), L(0), L(1, 0),
               L(3, 0xffff, 0xffff, 0xffff), L(-3, 1, 2, 0), L(10, *range(100, 110))]))
w("containers", st([st([b"i" + I(1)]), st([b"i" + I(1)]), bt([b"i" + I(1)]), bt([]), st([]),
                    b"[" + I(1) + b"N", b"[" + I(1) + b"N", b"<" + I(2) + b"NT", b"<" + I(2) + b"TN",
                    b">" + I(2) + b"NT", b">" + I(2) + b"NT", b":NNN", b":NNN", bt([b"N"] * 300)]))
w("singletons", st([bytes([ord("N") | F]), r(0), bytes([ord("T") | F]), r(1), b"S", b".", b"0",
                    bytes([ord(".") | F]), r(2)]))
w("references", st([st([z(b"x")]), st([z(b"x", f=F)]), r(0), z(b"q", f=F),
                    bytes([ord("r") | F]) + I(1), r(2)]))
w("trailing", st([z(b"x", f=F)]) + b"garbage")
w("forward", st([r(1), z(b"a", f=F)]))
w("within", st([r(0)], F))
w("unknown_type", st([b"q"]))
w("text_float", st([b"f\x030.0"]))
w("int64", st([b"I" + I(1) + I(0)]))
w("truncated", st([z(b"abc")])[:-1])
w("short", b"", MAGIC + b"\0" * 8)
w("magic_only", b"", MAGIC)
w("not_pyc", b"", b"hello, world\n")
w("unknown_magic", st([z(b"x", f=F)]), other(3355, 16))
w("python27", st([z(b"x", f=F)]), other(62211, 8))
w("python38", b"c" + I(0) * 6 + b"s" + I(2) + b"ab" + st([z(b"x"), z(b"x")]) + st([]) * 4
  + z(b"f.py") + z(b"<module>") + I(1) + b"s" + I(2) + b"ab", other(3413, 16))
w("python36", st([st([b"i" + I(1)]), st([b"i" + I(1)])]), other(3379, 12))
w("python32", st([st([b"i" + I(1)]), st([b"i" + I(1)])]), other(3180, 8))
w("python314", st([z(b"x"), z(b"x")]), other(3627, 16))
w("python316", st([z(b"x"), z(b"x")]), other(4000, 16))
"#;

/// Every entry under `root`, by path: what tar and dpkg keep of it (type, content or
/// link target, mode, owner, mtime to the nanosecond, link count), and its inode.
fn snapshot(root: &Path) -> Vec<(String, String, Vec<u8>, u64)> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            let meta = format!(
                "{:o} {}:{} {}.{:09} {}",
                m.mode(),
                m.uid(),
                m.gid(),
                m.mtime(),
                m.mtime_nsec(),
                m.nlink()
            );
            let content = if m.is_dir() {
                dirs.push(p);
                Vec::new()
            } else if m.is_symlink() {
                fs::read_link(&p)
                    .unwrap()
                    .into_os_string()
                    .into_encoded_bytes()
            } else {
                fs::read(&p).unwrap()
            };
            // a directory's mtime moves with the temporary files of both tools
            let meta = if m.is_dir() {
                format!("{:o}", m.mode())
            } else {
                meta
            };
            out.push((rel, meta, content, m.ino()));
        }
    }
    out.sort();
    out
}

/// Normalize copies of `tree` with add-determinism and with `ours` (the arguments
/// after the binary, the directory last), and require the same entries, and the same
/// files replaced by a new inode; the exit statuses of both.
fn compare(tree: &Path, ours: &[&str]) -> (Output, Output) {
    let parent = tree.parent().unwrap();
    let (real, mine) = (parent.join("real"), parent.join("ours"));
    for d in [&real, &mine] {
        run(Command::new("cp").arg("-a").arg(tree).arg(d));
    }
    let (real_before, mine_before) = (snapshot(&real), snapshot(&mine));
    let r = Command::new(ADD_DET)
        .arg(&real)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .unwrap();
    let o = Command::new(EXE)
        .args(ours)
        .arg(&mine)
        .env_remove("DEBBUILD_RS_STRIP_PYC")
        .output()
        .unwrap();
    let (rs, os) = (snapshot(&real), snapshot(&mine));
    assert_eq!(rs.len(), os.len());
    let mut differ = Vec::new();
    for (((a, b), a0), b0) in rs.iter().zip(&os).zip(&real_before).zip(&mine_before) {
        assert_eq!((&a.0, &b.0), (&a0.0, &b0.0), "the same entries");
        assert_eq!(a.0, b.0, "the same entries");
        let (ra, rb) = (a.3 != a0.3, b.3 != b0.3);
        if a.1 != b.1 || a.2 != b.2 || ra != rb {
            differ.push(format!(
                "{}: real {} {} bytes{}, ours {} {} bytes{}",
                a.0,
                a.1,
                a.2.len(),
                if ra { " replaced" } else { "" },
                b.1,
                b.2.len(),
                if rb { " replaced" } else { "" },
            ));
        }
    }
    assert!(
        differ.is_empty(),
        "{}\nreal: {}\nours: {}",
        differ.join("\n"),
        String::from_utf8_lossy(&r.stderr),
        String::from_utf8_lossy(&o.stderr)
    );
    (r, o)
}

/// Write `files` (path, content) under `root`.
fn write_sources(root: &Path, files: &[(&str, &str)]) {
    for (p, c) in files {
        let path = root.join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, c).unwrap();
    }
}

#[test]
fn pyc_compiled_by_python() {
    if !tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write_sources(&tree.join("src"), SOURCES);
    run(Command::new("python3").args(["-c", COMPILE]).arg(&tree));
    let (r, o) = compare(&tree, &["strip-nondeterminism", "--pyc"]);
    assert!(r.status.success() && o.status.success(), "{r:?}\n{o:?}");
    // the normalized files still load, and the modules still run
    let check = r#"
import importlib.util, marshal, os, sys
n = 0
for d, _, files in os.walk(sys.argv[1]):
    for f in files:
        if f.endswith(".pyc"):
            data = open(os.path.join(d, f), "rb").read()
            marshal.loads(data[16:])
            n += 1
sys.path.insert(0, os.path.join(sys.argv[1], "compileall-plain"))
import consts, pkg
assert consts.__cached__ and os.path.exists(consts.__cached__)
assert consts.result()[3][2] == "three" and pkg.value()["c"] == "a" * 300
print(n)
"#;
    let out = run(Command::new("python3")
        .args(["-B", "-c", check])
        .arg(tmp.path().join("ours")));
    let n: usize = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    assert!(n > 50, "{n} .pyc files");
}

#[test]
fn pyc_crafted_streams() {
    if !tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    run(Command::new("python3").args(["-c", CRAFT]).arg(&tree));
    let (r, o) = compare(&tree, &["strip-nondeterminism", "--pyc"]);
    assert!(r.status.success() && o.status.success(), "{r:?}\n{o:?}");
}

#[test]
fn pyc_files_on_disk() {
    if !tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    fs::create_dir_all(tree.join("sub/deeper")).unwrap();
    let pyc = |name: &str| {
        let p = tree.join(name);
        run(Command::new("python3")
            .arg("-c")
            .arg("import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)")
            .arg(tree.join("m.py"))
            .arg(&p));
        p
    };
    fs::write(
        tree.join("m.py"),
        "X = ('hello', 'hello'.upper())\ndef f():\n    return X\n",
    )
    .unwrap();
    for name in [
        "plain.pyc",
        "ro.pyc",
        "suid.pyc",
        "linked.pyc",
        "target.pyc",
        "sub/deeper/m.cpython-3.pyc",
        ".pyc",
        "x.pyo",
        "X.PYC",
        "x.pyc.orig",
        "nano.pyc",
        "owned.pyc",
    ] {
        pyc(name);
    }
    let sh = |script: &str| {
        run(Command::new("sh").arg("-c").arg(script).current_dir(&tree));
    };
    sh(
        "chmod 444 ro.pyc && chmod 4755 suid.pyc && ln linked.pyc sub/link.pyc \
        && ln -s target.pyc sym.pyc && ln -s sub subdir.pyc \
        && touch -d @1500000000 *.pyc *.py* .pyc X.PYC sub/deeper/*.pyc \
        && touch -d @1500000000.123456789 nano.pyc && touch -d @2000000000 target.pyc",
    );
    if nix_root() {
        sh("chown 1234:5678 owned.pyc");
    }
    let (r, o) = compare(&tree, &["strip-nondeterminism", "--pyc"]);
    assert!(r.status.success() && o.status.success(), "{r:?}\n{o:?}");
}

fn nix_root() -> bool {
    run(Command::new("id").arg("-u")).stdout.starts_with(b"0\n")
}

#[test]
fn pyc_too_short_fails_the_run() {
    if !tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    run(Command::new("python3").args(["-c", CRAFT]).arg(&tree));
    fs::write(tree.join("tiny.pyc"), b"\x0d\x0a").unwrap();
    let (r, o) = compare(&tree, &["strip-nondeterminism", "--pyc"]);
    assert!(!r.status.success() && !o.status.success(), "{r:?}\n{o:?}");
}

#[test]
fn pyc_twice_is_once() {
    if !tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write_sources(&tree.join("src"), SOURCES);
    run(Command::new("python3").args(["-c", COMPILE]).arg(&tree));
    for _ in 0..2 {
        run(Command::new(EXE)
            .args(["strip-nondeterminism", "--pyc"])
            .arg(&tree));
    }
    let once = snapshot(&tree);
    let o = run(Command::new(EXE)
        .args(["strip-nondeterminism", "--pyc", "-v"])
        .arg(&tree));
    assert!(o.stderr.is_empty(), "{o:?}");
    assert_eq!(snapshot(&tree), once);
}

/// A source package with binary package `pp`, holding the .pyc files of `tree`.
fn package(dir: &Path, tree: &Path) {
    fs::create_dir_all(dir.join("debian")).unwrap();
    fs::write(
        dir.join("debian/control"),
        "Source: pyc-test\nMaintainer: t <t@example.org>\nBuild-Depends: debhelper-compat (= 13)\n\nPackage: pp\nArchitecture: all\nDescription: x\n x\n",
    )
    .unwrap();
    fs::write(
        dir.join("debian/changelog"),
        "pyc-test (1.0) unstable; urgency=medium\n\n  * x\n\n -- t <t@example.org>  Mon, 14 Oct 2024 12:34:57 +0200\n",
    )
    .unwrap();
    run(Command::new("cp")
        .arg("-a")
        .arg(tree)
        .arg(dir.join("debian/pp")));
}

#[test]
fn pyc_dh_strip_nondeterminism_opt_in() {
    if !tools() {
        return;
    }
    if !have("dh_strip_nondeterminism") {
        skip("dh_strip_nondeterminism (debhelper)");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write_sources(&tree.join("src"), SOURCES);
    run(Command::new("python3").args(["-c", COMPILE]).arg(&tree));
    let bin = tmp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    symlink(EXE, bin.join("dh_strip_nondeterminism")).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let dh = |dir: &Path, ours: bool, pyc: &str| {
        let mut c = Command::new(if ours {
            bin.join("dh_strip_nondeterminism")
        } else {
            "dh_strip_nondeterminism".into()
        });
        run(c
            .current_dir(dir)
            .env("PATH", &path)
            .env("DEBBUILD_RS_STRIP_PYC", pyc)
            .env_remove("DH_OPTIONS"));
    };
    // without the variable, the package tree is debhelper's, .pyc files untouched
    let (real, ours) = (tmp.path().join("real"), tmp.path().join("ours"));
    package(&real, &tree);
    package(&ours, &tree);
    dh(&real, false, "");
    dh(&ours, true, "");
    // entries without their inode
    let entries = |root: &Path| {
        snapshot(root)
            .into_iter()
            .map(|e| (e.0, e.1, e.2))
            .collect::<Vec<_>>()
    };
    let pp = |d: &Path| entries(&d.join("debian/pp"));
    let orig = entries(&tree);
    assert_eq!(pp(&real), pp(&ours));
    assert_eq!(pp(&ours), orig);
    // with it: debhelper's helper, then add-determinism
    let (real, ours) = (tmp.path().join("real2"), tmp.path().join("ours2"));
    package(&real, &tree);
    package(&ours, &tree);
    dh(&real, false, "1");
    run(Command::new(ADD_DET).arg(real.join("debian/pp")));
    dh(&ours, true, "1");
    assert_eq!(pp(&real), pp(&ours));
    assert_ne!(pp(&ours), orig);
}
