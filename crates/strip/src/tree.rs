//! Files on disk: which handler takes each one, and writing the result back.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{
    Kind, Normalizers, Result, Target, by_name, confirms, confirms_magic, io_err, is_pyc_name,
    javadoc, zip,
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
        // only the descriptions (-b) are matched, never a path
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
/// others are dropped, as are those whose handler is not `enabled`. `forced` skips
/// detection, as `strip-nondeterminism -t` does; with `pyc`, the files named `*.pyc` are
/// Python bytecode, whatever their content.
pub fn classify(
    targets: Vec<Target>,
    forced: Option<Kind>,
    pyc: bool,
    enabled: Normalizers,
) -> Result<Vec<(Target, Kind)>> {
    if let Some(kind) = forced {
        return Ok(targets.into_iter().map(|t| (t, kind)).collect());
    }
    // (target, handler, the one its name asks for if the first is not confirmed, first
    // bytes) of the files whose name or content asks for one
    let mut candidates = Vec::new();
    for t in targets {
        let name = t
            .path
            .file_name()
            .map(OsStrExt::as_bytes)
            .unwrap_or_default();
        if pyc && is_pyc_name(name) {
            candidates.push((t, Kind::Pyc, None, Vec::new()));
            continue;
        }
        let kind = by_name(name).filter(|k| enabled.contains(*k));
        let head = head(&t.path)?;
        let kind = match kind {
            Some(Kind::Javadoc) if !javadoc::detect(&head) => None,
            k => k,
        };
        // a Python zip application, whatever its name, before what the name asks for
        let (kind, fallback) = match kind {
            _ if enabled.contains(Kind::Pyzip) && zip::is_pyzip(&head) => (Kind::Pyzip, kind),
            Some(k) => (k, None),
            None => continue,
        };
        candidates.push((t, kind, fallback, head));
    }
    let checked: Vec<&Path> = candidates
        .iter()
        .filter(|(_, k, f, _)| needs_file(*k) || f.is_some_and(needs_file))
        .map(|(t, _, _, _)| t.path.as_path())
        .collect();
    let mut descriptions = describe(&checked).map(Vec::into_iter);
    let mut out = Vec::with_capacity(candidates.len());
    for (t, kind, fallback, head) in candidates {
        let description = if needs_file(kind) || fallback.is_some_and(needs_file) {
            descriptions.as_mut().and_then(Iterator::next)
        } else {
            None
        };
        let confirmed = |k: Kind| {
            !needs_file(k)
                || match &description {
                    Some(d) => confirms(k, d),
                    None => confirms_magic(k, &head),
                }
        };
        if let Some(k) = [Some(kind), fallback]
            .into_iter()
            .flatten()
            .find(|&k| confirmed(k))
        {
            out.push((t, k));
        }
    }
    Ok(out)
}

fn needs_file(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Ar
            | Kind::Cpio
            | Kind::Gzip
            | Kind::Zip
            | Kind::Jar
            | Kind::Png
            | Kind::Gettext
            | Kind::Pyzip
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
    // set here, not at creation, where the umask would clear bits of it
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| io_err(tmp.path(), &e))?;
    tmp.persist(path).map_err(|e| io_err(path, &e.error))?;
    Ok(())
}

/// The regular files under `root` into `out`, in directory order, every name of each
/// inode, with the name they are reported under: `display` joined with the path below
/// `root`.
pub fn walk(root: &Path, display: &str, out: &mut Vec<Target>) -> Result<()> {
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
            } else if meta.is_file() {
                out.push(Target {
                    path,
                    display: shown,
                });
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(())
}
