//! Files on disk: which handler takes each one, and writing the result back.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{
    Kind, Result, Target, by_name, confirms, confirms_magic, io_err, is_pyc_name, javadoc,
};

/// The first bytes of a file, enough for the magic numbers and the javadoc marker.
fn head(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    File::open(path)
        .and_then(|f| f.take(1024).read_to_end(&mut buf))
        .map_err(|e| io_err(path, &e))?;
    Ok(buf)
}

/// file(1)'s description of each of `paths`, or `None` when file(1) cannot run.
fn describe(paths: &[&Path]) -> Option<Vec<String>> {
    let mut descriptions = Vec::with_capacity(paths.len());
    for chunk in paths.chunks(256) {
        let out = Command::new("file")
            .arg("-b")
            .arg("--")
            .args(chunk)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() != chunk.len() {
            return None;
        }
        descriptions.extend(lines);
    }
    Some(descriptions)
}

/// The handler of each target strip-nondeterminism would normalize, in order; the
/// others are dropped. `forced` skips detection, as `strip-nondeterminism -t` does;
/// with `pyc`, the files named `*.pyc` are Python bytecode, whatever their content.
pub fn classify(
    targets: Vec<Target>,
    forced: Option<Kind>,
    pyc: bool,
) -> Result<Vec<(Target, Kind)>> {
    if let Some(kind) = forced {
        return Ok(targets.into_iter().map(|t| (t, kind)).collect());
    }
    // (target, handler, first bytes) of the files whose name or content asks for one
    let mut candidates = Vec::new();
    for t in targets {
        let name = t
            .path
            .file_name()
            .map(OsStrExt::as_bytes)
            .unwrap_or_default();
        if pyc && is_pyc_name(name) {
            candidates.push((t, Kind::Pyc, Vec::new()));
            continue;
        }
        let kind = by_name(name);
        if let Some(k) = kind
            && !k.native()
        {
            // the real tool checks the content of these itself
            candidates.push((t, k, Vec::new()));
            continue;
        }
        let head = head(&t.path)?;
        // a Python zip application, whatever its name: a `#!` line, then a zip archive
        let pyzip = head.starts_with(b"#!")
            && fs::read(&t.path)
                .map_err(|e| io_err(&t.path, &e))?
                .windows(4)
                .any(|w| w == b"PK\x03\x04");
        let kind = match kind {
            _ if pyzip => Kind::Pyzip,
            Some(Kind::Javadoc) if !javadoc::detect(&head) => continue,
            Some(k) => k,
            None => continue,
        };
        candidates.push((t, kind, head));
    }
    let checked: Vec<&Path> = candidates
        .iter()
        .filter(|(_, k, _)| needs_file(*k))
        .map(|(t, _, _)| t.path.as_path())
        .collect();
    let mut descriptions = describe(&checked).map(Vec::into_iter);
    let mut out = Vec::with_capacity(candidates.len());
    for (t, kind, head) in candidates {
        let keep = if needs_file(kind) {
            match descriptions.as_mut().and_then(Iterator::next) {
                Some(d) => confirms(kind, &d),
                None => confirms_magic(kind, &head),
            }
        } else {
            true
        };
        if keep {
            out.push((t, kind));
        }
    }
    Ok(out)
}

fn needs_file(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Gzip | Kind::Zip | Kind::Jar | Kind::Png | Kind::Gettext | Kind::Pyzip
    )
}

/// Write `data` to `path`: over the file, which keeps its inode, links and mode, or,
/// with `replace`, as a new file with the same permissions renamed over it (owned by
/// this process, and no longer linked to the other names of the old one).
pub fn write(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    if !replace {
        return File::options()
            .write(true)
            .truncate(true)
            .open(path)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| io_err(path, &e));
    }
    let mode = fs::metadata(path).map_err(|e| io_err(path, &e))?.mode();
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".debbuild-rs-strip")
        .tempfile_in(dir)
        .map_err(|e| io_err(dir, &e))?;
    tmp.write_all(data).map_err(|e| io_err(tmp.path(), &e))?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| io_err(tmp.path(), &e))?;
    tmp.persist(path).map_err(|e| io_err(path, &e.error))?;
    Ok(())
}

/// The regular files under `root`, in directory order, each inode once (the first of
/// its names), with the name they are reported under: `display` joined with the path
/// below `root`.
pub fn walk(root: &Path, display: &str) -> Result<Vec<Target>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), display.to_owned())];
    while let Some((dir, shown)) = stack.pop() {
        let mut subdirs: Vec<(PathBuf, String)> = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| io_err(&dir, &e))? {
            let entry = entry.map_err(|e| io_err(&dir, &e))?;
            let path = entry.path();
            let name = entry.file_name();
            let shown = format!("{shown}/{}", name.to_string_lossy());
            let meta = fs::symlink_metadata(&path).map_err(|e| io_err(&path, &e))?;
            if meta.is_dir() {
                subdirs.push((path, shown));
            } else if meta.is_file() && (meta.nlink() == 1 || seen.insert((meta.dev(), meta.ino())))
            {
                out.push(Target {
                    path,
                    display: shown,
                });
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(out)
}
