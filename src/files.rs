//! File writes for key material.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::error::Error;

/// Writes a new file, refusing to replace one. Key files are owner-only.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| Error::io(path, e))?;
    file.write_all(bytes).map_err(|e| Error::io(path, e))?;
    file.sync_all().map_err(|e| Error::io(path, e))
}
