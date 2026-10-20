//! Python bytecode (`.pyc`), normalized as add-determinism 0.7.3 does. Not a
//! strip-nondeterminism handler: the callers enable it on request.
//!
//! A .pyc file is a header (since Python 3.7, PEP 552's 16 bytes: the magic number, the
//! flags, then the mtime and size of the source or its hash; 12 bytes on 3.3 to 3.6, 8
//! before) and a code object in the marshal format. marshal writes an object it meets
//! again as a reference (`r` and an index) only if it flagged the first one (`FLAG_REF`,
//! bit 7 of the type byte), and it flags the objects the interpreter holds more than one
//! reference to at that moment: the flags, and which equal objects are written twice,
//! depend on the history of the process that compiled the file.
//!
//! The normalized stream depends on the values only. An object equal to one written
//! before it is written as a reference to that one: same type and content (strings of
//! different types differ; integers compare by value within their form, floats and
//! complex numbers by their bits; both tuple forms are tuples; containers and code
//! objects compare item by item). An object is flagged if, and only if, it is referenced,
//! and the flagged objects are numbered in the order they are written. None, the
//! booleans, `StopIteration`, Ellipsis and NULL are written as themselves, never flagged.
//! A tuple of fewer than 256 items takes the short form, an integer in the long form its
//! canonical digits (add-determinism reads each 15-bit digit as a signed 16-bit number,
//! which only matters for digits `CPython` rejects). The header is kept, bytes after the
//! code object are dropped with a warning.
//!
//! The magic numbers are `CPython`'s (`Include/internal/pycore_magic_number.h`), grouped
//! into the versions 3.0 to 3.16 with the boundaries that give add-determinism's output,
//! and the code object layouts of 3.0 to 3.7, 3.8 to 3.10 and 3.11 on. Files of Python 1
//! and 2 are left as they are; other magic numbers, objects add-determinism does not
//! rewrite (floats and complex numbers in text form, 64-bit integers, dictionaries) and
//! malformed streams are left as they are with a warning ([`Error::Malformed`]).
//!
//! The rewritten file replaces the old one with the same permissions, owner (where the
//! process may set it) and modification time; a file with other hard links is rewritten
//! in place instead, keeping its modification time.
//!
//! Written from the marshal format (`CPython`'s documentation and Python/marshal.c) and
//! from add-determinism 0.7.3's observable behaviour: its output on the .pyc files Python
//! 3.11 and 3.13 compile and on crafted streams, without reference to its source.

use std::fs::{self, File, Metadata};
use std::hash::{BuildHasherDefault, Hasher};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use indexmap::IndexSet;

use crate::{Error, Result, io_err};

const FLAG_REF: u8 = 0x80;
/// Nesting deeper than `CPython`'s marshal reads is malformed.
const MAX_DEPTH: usize = 2000;

/// The code object layout of a Python version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    /// Header bytes before the marshal stream.
    header: usize,
    /// 32-bit integers before the first object.
    ints: usize,
    /// Objects after `co_firstlineno` (8 before it on every version).
    after: usize,
}

/// `CPython`'s magic numbers of each Python 3 version, as ranges, with the minor version.
const PY3: &[(u16, u16, u8)] = &[
    (3000, 3131, 0),
    (3132, 3160, 1),
    (3161, 3180, 2),
    (3181, 3230, 3),
    (3231, 3310, 4),
    (3311, 3351, 5),
    (3360, 3361, 6),
    (3370, 3379, 6),
    (3390, 3394, 7),
    (3400, 3401, 8),
    (3402, 3409, 9),
    (3410, 3413, 8),
    (3414, 3425, 9),
    (3430, 3439, 10),
    (3450, 3495, 11),
    (3500, 3531, 12),
    (3550, 3599, 13),
    (3600, 3649, 14),
    (3650, 3699, 15),
    (3700, 4000, 16),
];

/// The magic numbers of Python 1.5 to 2.7: left as they are.
const PY2: &[u16] = &[
    20121, 50428, 50823, 60202, 60717, 62011, 62021, 62041, 62051, 62061, 62071, 62081, 62091,
    62092, 62101, 62111, 62121, 62131, 62151, 62161, 62171, 62181, 62191, 62201, 62211,
];

fn layout(minor: u8) -> Layout {
    let header = match minor {
        0..=2 => 8,
        3..=6 => 12,
        _ => 16,
    };
    match minor {
        0..=7 => Layout {
            header,
            ints: 5,
            after: 1,
        },
        8..=10 => Layout {
            header,
            ints: 6,
            after: 1,
        },
        _ => Layout {
            header,
            ints: 5,
            after: 2,
        },
    }
}

fn malformed(msg: impl Into<String>) -> Error {
    Error::malformed(msg)
}

/// A value of the stream, children by their [`Id`]: equal values are one. Bytes are
/// borrowed from the file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Val<'a> {
    /// None, False, True, `StopIteration`, Ellipsis or NULL: the type byte.
    Single(u8),
    /// A value written as its type byte and these bytes (int, binary float and complex,
    /// strings and bytes with their length).
    Raw(u8, &'a [u8]),
    /// An integer in the long form: negative, 15-bit digits from the least significant,
    /// the most significant non-zero.
    Long(bool, Vec<u16>),
    /// A tuple (`(`), list, set, frozenset or slice (`:`).
    Seq(u8, Vec<Id>),
    /// A code object: its integers before the first object as written, the objects,
    /// and `co_firstlineno` as written.
    Code(&'a [u8], Vec<Id>, [u8; 4]),
}

type Id = usize;

/// rustc's `FxHash`: the values come from the package's own build, `SipHash`'s resistance
/// to chosen keys is not worth its cost.
#[derive(Default)]
struct FxHasher(u64);

impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for w in words {
            self.add(u64::from_le_bytes(*w));
        }
        let mut last = [0_u8; 8];
        if let Some(dst) = last.get_mut(..rest.len()) {
            dst.copy_from_slice(rest);
            self.add(u64::from_le_bytes(last) ^ u64::try_from(rest.len()).unwrap_or(0) << 56);
        }
    }

    fn write_u8(&mut self, n: u8) {
        self.add(u64::from(n));
    }

    fn write_usize(&mut self, n: usize) {
        self.add(u64::try_from(n).unwrap_or(u64::MAX));
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

impl FxHasher {
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    layout: Layout,
    /// The distinct values, an [`Id`] their index.
    values: IndexSet<Val<'a>, BuildHasherDefault<FxHasher>>,
    /// The objects flagged so far, by reference index; `None` while being read.
    refs: Vec<Option<Id>>,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn eof(&self, n: usize) -> Error {
        malformed(format!(
            "unexpected end of file, {n} bytes wanted at offset {:#x}",
            self.pos
        ))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.eof(n))?;
        let s = self.data.get(self.pos..end).ok_or_else(|| self.eof(n))?;
        self.pos = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8> {
        let s = self.take(1)?;
        s.first().copied().ok_or_else(|| self.eof(1))
    }

    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        let b = s.first_chunk::<4>().ok_or_else(|| self.eof(4))?;
        Ok(u32::from_le_bytes(*b))
    }

    fn count(&mut self) -> Result<usize> {
        let n = self.u32()?;
        usize::try_from(n).map_err(|_| self.eof(usize::MAX))
    }

    fn intern(&mut self, v: Val<'a>) -> Id {
        self.values.insert_full(v).0
    }

    fn items(&mut self, n: usize) -> Result<Vec<Id>> {
        // the count is untrusted: every item takes at least a byte
        let mut v = Vec::with_capacity(n.min(self.data.len().saturating_sub(self.pos)));
        for _ in 0..n {
            v.push(self.object()?);
        }
        Ok(v)
    }

    fn object(&mut self) -> Result<Id> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            return Err(malformed("objects nested too deep"));
        }
        let id = self.object_at_depth();
        self.depth = self.depth.saturating_sub(1);
        id
    }

    fn object_at_depth(&mut self) -> Result<Id> {
        let at = self.pos;
        let t = self.byte()?;
        let code = t & !FLAG_REF;
        let flagged = t & FLAG_REF != 0;
        if code == b'r' {
            let i = self.u32()?;
            let id = match usize::try_from(i).ok().and_then(|i| self.refs.get(i)) {
                Some(Some(id)) => *id,
                Some(None) => {
                    return Err(malformed(format!(
                        "reference {i} at offset {at:#x} into the object being read"
                    )));
                }
                None => {
                    return Err(malformed(format!(
                        "reference {i} at offset {at:#x} to no flagged object"
                    )));
                }
            };
            if flagged {
                self.refs.push(Some(id));
            }
            return Ok(id);
        }
        let slot = flagged.then(|| {
            self.refs.push(None);
            self.refs.len().saturating_sub(1)
        });
        let val = match code {
            b'0' | b'N' | b'F' | b'T' | b'S' | b'.' => Val::Single(code),
            b'i' => Val::Raw(code, self.take(4)?),
            b'g' => Val::Raw(code, self.take(8)?),
            b'y' => Val::Raw(code, self.take(16)?),
            b's' | b't' | b'u' | b'a' | b'A' => {
                let start = self.pos;
                let n = self.count()?;
                self.take(n)?;
                Val::Raw(code, self.data.get(start..self.pos).unwrap_or_default())
            }
            b'z' | b'Z' => {
                let start = self.pos;
                let n = self.byte()?;
                self.take(usize::from(n))?;
                Val::Raw(code, self.data.get(start..self.pos).unwrap_or_default())
            }
            b'l' => {
                let n = self.u32()?;
                let (negative, len) = (n & 0x8000_0000 != 0, n.cast_signed().unsigned_abs());
                let len = usize::try_from(len).map_err(|_| self.eof(usize::MAX))?;
                let raw = self.take(len.saturating_mul(2))?;
                let digits: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|d| u16::from_le_bytes(*d))
                    .collect();
                let (neg, digits) = canonical_long(negative, &digits);
                Val::Long(neg, digits)
            }
            b')' => {
                let n = self.byte()?;
                Val::Seq(b'(', self.items(usize::from(n))?)
            }
            b'(' | b'[' | b'<' | b'>' => {
                let n = self.count()?;
                Val::Seq(code, self.items(n)?)
            }
            b':' => Val::Seq(code, self.items(3)?),
            b'c' => {
                let ints = self.take(self.layout.ints.saturating_mul(4))?;
                let mut objs = self.items(8)?;
                let line = *self
                    .take(4)?
                    .first_chunk::<4>()
                    .ok_or_else(|| self.eof(4))?;
                objs.extend(self.items(self.layout.after)?);
                Val::Code(ints, objs, line)
            }
            b'f' | b'x' | b'I' | b'{' => {
                return Err(malformed(format!(
                    "object of type '{}' at offset {at:#x}, which add-determinism does not rewrite",
                    char::from(code)
                )));
            }
            _ => {
                return Err(malformed(format!(
                    "unknown object type {code} at offset {at:#x}"
                )));
            }
        };
        let id = self.intern(val);
        if let Some(slot) = slot.and_then(|s| self.refs.get_mut(s)) {
            *slot = Some(id);
        }
        Ok(id)
    }
}

/// The sign and canonical digits of the long integer written with `digits`, each
/// read as a signed 16-bit number as add-determinism reads them.
fn canonical_long(negative: bool, digits: &[u16]) -> (bool, Vec<u16>) {
    const BASE: i32 = 1 << 15;
    // sum of d * BASE^i: carry the excess along, the last carry is in -2..=0
    let mut out = Vec::with_capacity(digits.len().saturating_add(1));
    let mut carry = 0_i32;
    for &d in digits {
        let t = i32::from(d.cast_signed()).saturating_add(carry);
        out.push(u16::try_from(t.rem_euclid(BASE)).unwrap_or(0));
        carry = t.div_euclid(BASE);
    }
    let mut neg = false;
    if carry < 0 {
        // the value is carry * BASE^n + out: its magnitude is the negation
        neg = true;
        let mut borrow = 0_i32;
        for d in &mut out {
            let t = borrow.saturating_sub(i32::from(*d));
            *d = u16::try_from(t.rem_euclid(BASE)).unwrap_or(0);
            borrow = t.div_euclid(BASE);
        }
        out.push(u16::try_from(borrow.saturating_sub(carry)).unwrap_or(0));
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    (!out.is_empty() && neg != negative, out)
}

/// What [`Writer`] knows of a value, by [`Id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Not met yet.
    No,
    /// Met once ([`Writer::scan`]), or written unflagged ([`Writer::write`]).
    Once,
    /// Met more than once: flagged where first written.
    Shared,
    /// Written flagged, with this reference index.
    Ref(u32),
}

/// Writes the values from the root, each equal value once.
struct Writer<'p, 'a> {
    values: &'p IndexSet<Val<'a>, BuildHasherDefault<FxHasher>>,
    seen: Vec<Seen>,
    next: u32,
    out: Vec<u8>,
}

impl Writer<'_, '_> {
    /// Find the values met more than once, in the order [`Writer::write`] meets them.
    fn scan(&mut self, id: Id) {
        let values = self.values;
        let (Some(v), Some(seen)) = (values.get_index(id), self.seen.get_mut(id)) else {
            return;
        };
        match (v, *seen) {
            (Val::Single(_), _) => return,
            (_, Seen::No) => *seen = Seen::Once,
            _ => {
                *seen = Seen::Shared;
                return;
            }
        }
        if let Val::Seq(_, kids) | Val::Code(_, kids, _) = v {
            for &k in kids {
                self.scan(k);
            }
        }
    }

    fn i32(&mut self, n: usize) {
        let n = u32::try_from(n).unwrap_or(u32::MAX);
        self.out.extend_from_slice(&n.to_le_bytes());
    }

    /// Write the value `id`, after [`Writer::scan`] from the root: [`Seen::Once`] is
    /// then not written yet, [`Seen::No`] written unflagged (a value met once is written
    /// once).
    fn write(&mut self, id: Id) {
        let values = self.values;
        let (Some(v), Some(seen)) = (values.get_index(id), self.seen.get_mut(id)) else {
            return;
        };
        if let Val::Single(code) = v {
            self.out.push(*code);
            return;
        }
        let flag = match *seen {
            Seen::Once => {
                *seen = Seen::No;
                0
            }
            Seen::Shared => {
                *seen = Seen::Ref(self.next);
                self.next = self.next.saturating_add(1);
                FLAG_REF
            }
            Seen::Ref(index) => {
                self.out.push(b'r');
                self.out.extend_from_slice(&index.to_le_bytes());
                return;
            }
            Seen::No => return,
        };
        match v {
            Val::Single(_) => {}
            Val::Raw(code, raw) => {
                self.out.push(code | flag);
                self.out.extend_from_slice(raw);
            }
            Val::Long(neg, digits) => {
                self.out.push(b'l' | flag);
                let n = i32::try_from(digits.len()).unwrap_or(i32::MAX);
                let n = if *neg { n.saturating_neg() } else { n };
                self.out.extend_from_slice(&n.to_le_bytes());
                for d in digits {
                    self.out.extend_from_slice(&d.to_le_bytes());
                }
            }
            Val::Seq(code, kids) => {
                match (code, u8::try_from(kids.len())) {
                    (b'(', Ok(n)) => self.out.extend_from_slice(&[b')' | flag, n]),
                    (b':', _) => self.out.push(b':' | flag),
                    _ => {
                        self.out.push(code | flag);
                        self.i32(kids.len());
                    }
                }
                for &k in kids {
                    self.write(k);
                }
            }
            Val::Code(ints, kids, line) => {
                self.out.push(b'c' | flag);
                self.out.extend_from_slice(ints);
                let (before, after) = kids.split_at(kids.len().min(8));
                for &k in before {
                    self.write(k);
                }
                self.out.extend_from_slice(line);
                for &k in after {
                    self.write(k);
                }
            }
        }
    }
}

/// The layout of the file's Python version; `None` for Python 1 and 2.
fn version(data: &[u8]) -> Result<Option<Layout>> {
    let Some(magic) = data.first_chunk::<4>() else {
        return Err(malformed("too short for a magic number"));
    };
    if magic[2..] != *b"\r\n" {
        return Err(malformed("not a pyc file, no CR LF after the magic number"));
    }
    let m = u16::from_le_bytes([magic[0], magic[1]]);
    if PY2.contains(&m) {
        return Ok(None);
    }
    let Some(&(_, _, minor)) = PY3.iter().find(|(lo, hi, _)| (*lo..=*hi).contains(&m)) else {
        return Err(malformed(format!(
            "not a pyc file, unknown magic number {m}"
        )));
    };
    let l = layout(minor);
    if data.len() < l.header {
        return Err(malformed(format!(
            "too short for the header of Python 3.{minor} ({} < {})",
            data.len(),
            l.header
        )));
    }
    Ok(Some(l))
}

/// The normalized file, or `None` when it stays as it is (already normalized, or
/// Python 1 or 2). `warn` gets the warnings add-determinism prints and carries on.
///
/// # Errors
/// [`Error::Malformed`]: the file is not one this handler rewrites; add-determinism
/// leaves it as it is, with a warning.
pub fn normalize(data: &[u8], warn: &mut dyn FnMut(String)) -> Result<Option<Vec<u8>>> {
    let Some(layout) = version(data)? else {
        return Ok(None);
    };
    let mut p = Parser {
        data,
        pos: layout.header,
        layout,
        // one distinct value every 44 bytes on average in the .pyc files of Python's
        // library: rarely grown
        values: IndexSet::with_capacity_and_hasher(data.len() / 32, BuildHasherDefault::default()),
        refs: Vec::new(),
        depth: 0,
    };
    let root = p.object()?;
    let trailing = data.len().saturating_sub(p.pos);
    if trailing > 0 {
        warn(format!("{trailing} bytes after the code object, dropped"));
    }
    let mut w = Writer {
        values: &p.values,
        seen: vec![Seen::No; p.values.len()],
        next: 0,
        out: Vec::with_capacity(data.len()),
    };
    w.scan(root);
    w.out
        .extend_from_slice(data.get(..layout.header).unwrap_or_default());
    w.write(root);
    Ok((w.out != data).then_some(w.out))
}

/// What [`prepare`] makes of a file.
#[derive(Debug)]
pub enum Prepared {
    /// To be rewritten with this content ([`write_back`]).
    Rewrite(Vec<u8>, Metadata),
    /// Already normalized, or a file this handler leaves alone silently.
    Unchanged,
    /// Left as it is, with this warning.
    Skipped(String),
}

/// Read and normalize the .pyc file at `path` on disk, as add-determinism does: only a
/// regular file is read; a file add-determinism cannot process is left as it is with a
/// warning. `warn` gets the other warnings.
///
/// # Errors
/// The file cannot be read, or is too short for a magic number (add-determinism fails
/// the run for these, after the other files).
pub fn prepare(path: &Path, warn: &mut dyn FnMut(String)) -> Result<Prepared> {
    let meta = fs::symlink_metadata(path).map_err(|e| io_err(path, &e))?;
    if !meta.is_file() {
        return Ok(Prepared::Skipped("not a regular file".to_owned()));
    }
    let data = fs::read(path).map_err(|e| io_err(path, &e))?;
    if data.len() < 4 {
        return Err(Error::Io(format!(
            "{}: too short for a magic number",
            path.display()
        )));
    }
    match normalize(&data, warn) {
        Ok(Some(new)) if new != data => Ok(Prepared::Rewrite(new, meta)),
        Ok(_) => Ok(Prepared::Unchanged),
        Err(Error::Malformed(m, _)) => Ok(Prepared::Skipped(m)),
        Err(e) => Err(e),
    }
}

/// Write `data` as the new content of `path`, keeping its modification time: a new
/// file with its permissions and owner renamed over it, or, when it has other hard
/// links, over the file itself. `meta` is the file's, from [`prepare`].
///
/// # Errors
/// The file cannot be written.
pub fn write_back(
    path: &Path,
    meta: &Metadata,
    data: &[u8],
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    let mtime = meta.modified().map_err(|e| io_err(path, &e))?;
    if meta.nlink() > 1 {
        let mut f = File::options()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| io_err(path, &e))?;
        f.write_all(data).map_err(|e| io_err(path, &e))?;
        return f.set_modified(mtime).map_err(|e| io_err(path, &e));
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".debbuild-rs-pyc")
        .tempfile_in(dir)
        .map_err(|e| io_err(dir, &e))?;
    tmp.write_all(data).map_err(|e| io_err(tmp.path(), &e))?;
    let f = tmp.as_file();
    f.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777))
        .map_err(|e| io_err(tmp.path(), &e))?;
    // after the mode, as add-determinism: the kernel clears set-user-ID and set-group-ID
    if std::os::unix::fs::fchown(f, Some(meta.uid()), Some(meta.gid())).is_err() {
        warn("cannot keep the owner, ignoring".to_owned());
    }
    f.set_modified(mtime).map_err(|e| io_err(tmp.path(), &e))?;
    tmp.persist(path).map_err(|e| io_err(path, &e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const H311: &[u8] = b"\xa7\x0d\x0d\x0a\0\0\0\0\0\0\0\0\0\0\0\0";

    fn norm(body: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut warnings = Vec::new();
        let r = normalize(&[H311, body].concat(), &mut |w| warnings.push(w));
        assert!(warnings.is_empty(), "{warnings:?}");
        r
    }

    /// The normalized body, or the same body when nothing changes.
    fn body(body: &[u8]) -> Vec<u8> {
        norm(body)
            .unwrap()
            .map_or_else(|| body.to_vec(), |v| v[16..].to_vec())
    }

    #[test]
    fn flags_and_references() {
        // a flagged string never referenced loses its flag
        assert_eq!(body(b")\x01\xda\x01x"), b")\x01\x5a\x01x");
        // equal strings: the second is a reference to the first, now flagged
        assert_eq!(
            body(b")\x02z\x01xz\x01x"),
            b")\x02\xfa\x01xr\x00\x00\x00\x00"
        );
        // strings of different types are different values
        assert_eq!(body(b")\x02z\x01xZ\x01x"), b")\x02z\x01xZ\x01x");
        // references are renumbered in the order of the flagged objects
        assert_eq!(
            body(b")\x04\xfa\x01a\xfa\x01b\xfa\x01cr\x02\x00\x00\x00"),
            b")\x04z\x01az\x01b\xfa\x01cr\x00\x00\x00\x00"
        );
        // already normalized
        assert_eq!(norm(b")\x02\xfa\x01xr\x00\x00\x00\x00").unwrap(), None);
    }

    #[test]
    fn values() {
        // both tuple forms are tuples; the short form is written
        assert_eq!(
            body(b")\x02(\x01\x00\x00\x00N)\x01N"),
            b")\x02\xa9\x01Nr\x00\x00\x00\x00"
        );
        // floats by their bits: 0.0 and -0.0 differ
        let z = 0.0_f64.to_le_bytes();
        let nz = (-0.0_f64).to_le_bytes();
        let input = [&b")\x03g"[..], &z, b"g", &nz, b"g", &z].concat();
        let want = [&b")\x03\xe7"[..], &z, b"g", &nz, b"r\0\0\0\0"].concat();
        assert_eq!(body(&input), want);
        // singletons are never flagged, references to them become them
        assert_eq!(body(b")\x03\xce\xd4r\x00\x00\x00\x00"), b")\x03NTN");
        // lists, sets and frozensets compare item by item, in their order
        assert_eq!(
            body(b")\x03<\x01\x00\x00\x00N>\x01\x00\x00\x00N<\x01\x00\x00\x00N"),
            b")\x03\xbc\x01\x00\x00\x00N>\x01\x00\x00\x00Nr\x00\x00\x00\x00"
        );
    }

    #[test]
    fn longs() {
        let l = |n: i32, d: &[u16]| {
            let mut v = b"l".to_vec();
            v.extend_from_slice(&n.to_le_bytes());
            for x in d {
                v.extend_from_slice(&x.to_le_bytes());
            }
            v
        };
        for (input, want) in [
            (l(1, &[5]), l(1, &[5])),
            (l(-2, &[0x7fff, 3]), l(-2, &[0x7fff, 3])),
            (l(2, &[1, 0]), l(1, &[1])),
            (l(-1, &[0]), l(0, &[])),
            (l(1, &[0x8000]), l(-2, &[0, 1])),
            (l(2, &[0xffff, 1]), l(1, &[0x7fff])),
            (l(3, &[0xffff, 0xffff, 0xffff]), l(-3, &[1, 1, 1])),
            (l(2, &[0x8000, 0x7fff]), l(2, &[0, 0x7ffe])),
            (l(-3, &[1, 2, 0]), l(-2, &[1, 2])),
        ] {
            assert_eq!(body(&input), want, "{input:?}");
        }
    }

    #[test]
    fn code_objects() {
        // a 3.11 code object: 5 integers, 8 objects, firstlineno, 2 objects
        let code = |name: &[u8]| {
            let mut v = b"c".to_vec();
            v.extend_from_slice(&[0; 20]);
            v.extend_from_slice(b"s\x00\x00\x00\x00");
            for _ in 0..4 {
                v.extend_from_slice(b")\x00");
            }
            v.extend_from_slice(b"z\x04f.py");
            v.extend_from_slice(name);
            v.extend_from_slice(name);
            v.extend_from_slice(&7_i32.to_le_bytes());
            v.extend_from_slice(b"s\x00\x00\x00\x00s\x00\x00\x00\x00");
            v
        };
        let out = body(&code(b"z\x01f"));
        let mut want = b"c".to_vec();
        want.extend_from_slice(&[0; 20]);
        want.extend_from_slice(b"\xf3\x00\x00\x00\x00\xa9\x00");
        want.extend_from_slice(&b"r\x01\x00\x00\x00".repeat(3));
        want.extend_from_slice(b"z\x04f.py\xfa\x01fr\x02\x00\x00\x00");
        want.extend_from_slice(&7_i32.to_le_bytes());
        want.extend_from_slice(b"r\x00\x00\x00\x00r\x00\x00\x00\x00");
        assert_eq!(out, want);
        // equal code objects are one
        let two = [&b")\x02"[..], &code(b"z\x01g"), &code(b"z\x01g")].concat();
        assert!(body(&two).ends_with(b"r\x00\x00\x00\x00"));
    }

    #[test]
    fn headers_and_versions() {
        let mut w = |_| {};
        // the header is kept, whatever its flags and fields
        let mut f = b"\xf3\x0d\x0d\x0a\x03\0\0\0\x11\x22\x33\x44\x55\x66\x77\x88".to_vec();
        f.extend_from_slice(b"\xda\x01x");
        let out = normalize(&f, &mut w).unwrap().unwrap();
        assert_eq!(out[..16], f[..16]);
        assert_eq!(out[16..], *b"Z\x01x");
        // Python 2.7 is left alone; unknown magic numbers and short files are malformed
        assert_eq!(
            normalize(b"\x03\xf3\x0d\x0a\0\0\0\0\xda\x01x", &mut w).unwrap(),
            None
        );
        assert!(normalize(b"\x1b\x0d\x0d\x0a\0\0\0\0\0\0\0\0\0\0\0\0N", &mut w).is_err());
        assert!(normalize(b"\xa7\x0d\x0a\x0d\0\0\0\0\0\0\0\0\0\0\0\0N", &mut w).is_err());
        assert!(normalize(&H311[..15], &mut w).is_err());
        assert!(normalize(b"\xa7\x0d", &mut w).is_err());
        // a 3.8 code object: 6 integers, one object after firstlineno, 16-byte header
        let mut f = b"\x55\x0d\x0d\x0a\0\0\0\0\0\0\0\0\0\0\0\0c".to_vec();
        f.extend_from_slice(&[0; 24]);
        f.extend_from_slice(&b"N".repeat(8));
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(b"\xceN");
        assert_eq!(
            normalize(&f, &mut w).unwrap().unwrap()[16..].last(),
            Some(&b'N')
        );
        // a 3.2 file has an 8-byte header
        let f = b"\x6c\x0c\x0d\x0a\0\0\0\0)\x02z\x01xz\x01x";
        assert_eq!(
            normalize(f, &mut w).unwrap().unwrap()[8..],
            *b")\x02\xfa\x01xr\x00\x00\x00\x00"
        );
    }

    #[test]
    fn malformed_streams() {
        for bad in [
            &b")\x01"[..],
            b"(\xff\xff\xff\xff",
            b"q",
            b")\x01r\x00\x00\x00\x00",
            b"\xa9\x01r\x00\x00\x00\x00",
            b"{z\x01kN0",
            b"f\x030.0",
            b"a\xff\xff\xff\xff",
        ] {
            assert!(matches!(norm(bad), Err(Error::Malformed(..))), "{bad:?}");
        }
        // trailing bytes are dropped, with a warning
        let mut warnings = Vec::new();
        let out = normalize(&[H311, b"NN"].concat(), &mut |w| warnings.push(w)).unwrap();
        assert_eq!(out.unwrap()[16..], *b"N");
        assert_eq!(warnings.len(), 1);
        // nesting is bounded (on a stack for the depth of debug builds)
        let deep = [b")\x01".repeat(5000), b"N".to_vec()].concat();
        let t = std::thread::Builder::new().stack_size(64 << 20);
        assert!(
            t.spawn(move || norm(&deep).is_err())
                .unwrap()
                .join()
                .unwrap()
        );
    }
}
