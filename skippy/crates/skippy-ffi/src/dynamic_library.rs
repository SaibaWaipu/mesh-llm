use libloading::Library;
use std::error::Error;
use std::io;
use std::path::Path;

fn format_load_error(path: &Path, error: &libloading::Error) -> String {
    let detail = match error.source() {
        Some(source) => describe_source(source),
        None => format!("OS error {}", source_less_os_error_label(error)),
    };
    format!(
        "failed to load native runtime library {}: {} ({detail})",
        path.display(),
        error,
    )
}

/// Render the OS-level detail carried by a `libloading::Error`'s source.
///
/// libloading 0.9 moved its platform error types into a private module, so the
/// concrete `WindowsError`/`DlError` is no longer reachable from other crates and
/// does not downcast to [`io::Error`]. Its `Display` still carries the code
/// though: on Windows `WindowsError` delegates to
/// [`io::Error::from_raw_os_error`] and renders as e.g.
/// `The specified module could not be found. (os error 126)`, which is what makes
/// a failed `LoadLibraryExW` — for instance an architecture mismatch between a
/// native runtime DLL and the process — diagnosable.
fn describe_source(source: &(dyn Error + 'static)) -> String {
    match source.downcast_ref::<io::Error>() {
        Some(os_error) => format!(
            "OS error {}: {}",
            os_error.raw_os_error().unwrap_or(0),
            os_error,
        ),
        None => format!("OS error: {source}"),
    }
}

fn source_less_os_error_label(error: &libloading::Error) -> &'static str {
    #[cfg(target_os = "windows")]
    {
        if matches!(error, libloading::Error::LoadLibraryExWUnknown) {
            "0"
        } else {
            "unavailable"
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = error;
        "unavailable"
    }
}

#[cfg(target_os = "windows")]
pub(crate) unsafe fn load(path: &Path) -> Result<Library, String> {
    use libloading::os::windows::{LOAD_WITH_ALTERED_SEARCH_PATH, Library as WindowsLibrary};

    // LoadLibraryExW normally searches the application directory for a
    // dependent DLL, even when the requested DLL has an absolute path. Native
    // runtimes are installed elsewhere, so make the loaded DLL's directory the
    // first dependency search location.
    // Native runtime manifests declare their libraries with POSIX separators
    // and Path::join keeps them, so runtime library paths reach this point
    // with a mixed-separator tail (`...\lib/llama.dll`). LoadLibraryExW fails
    // those with ERROR_MOD_NOT_FOUND even though the file exists, and
    // LOAD_WITH_ALTERED_SEARCH_PATH cannot derive the dependency directory
    // from them. Rebuilding the path from its components normalizes every
    // separator to a backslash.
    let normalized: std::path::PathBuf = path.components().collect();
    let result =
        unsafe { WindowsLibrary::load_with_flags(&normalized, LOAD_WITH_ALTERED_SEARCH_PATH) };
    result
        .map(Into::into)
        .map_err(|error| format_load_error(path, &error))
}

#[cfg(not(target_os = "windows"))]
pub(crate) unsafe fn load(path: &Path) -> Result<Library, String> {
    unsafe { Library::new(path) }.map_err(|error| format_load_error(path, &error))
}

#[cfg(test)]
mod tests {
    use super::format_load_error;
    use libloading::Library;
    use std::path::Path;

    #[test]
    fn load_error_includes_library_path_and_os_error() {
        let path = Path::new("mesh-llm-missing-native-runtime.dll");
        let expected_error = match unsafe { Library::new(path) } {
            Ok(_) => panic!("unexpectedly loaded missing test library"),
            Err(error) => error,
        };

        let message =
            unsafe { super::load(path) }.expect_err("unexpectedly loaded missing test library");
        assert!(message.contains(path.to_string_lossy().as_ref()));
        assert!(message.contains("OS error"));
        assert!(message.contains(&expected_error.to_string()));

        if let Some(os_error) = std::error::Error::source(&expected_error)
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            && let Some(code) = os_error.raw_os_error()
        {
            assert!(message.contains(&format!("OS error {code}")));
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn source_less_non_windows_errors_report_unavailable_os_error() {
        let path = Path::new("mesh-llm-missing-native-runtime.dll");
        let message = format_load_error(path, &libloading::Error::DlOpenUnknown);

        assert!(message.contains("OS error unavailable"));
        assert!(!message.contains("OS error 0"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn load_error_reports_windows_os_error_detail() {
        // libloading 0.9 no longer exposes its `WindowsError` type, but the
        // source's `Display` still carries the code. A missing DLL fails
        // LoadLibraryExW with ERROR_MOD_NOT_FOUND (126); regressing to
        // `OS error unavailable` here is what makes a failed native-runtime load
        // impossible to diagnose.
        let path = Path::new("mesh-llm-missing-native-runtime.dll");
        let message =
            unsafe { super::load(path) }.expect_err("unexpectedly loaded missing test library");

        assert!(
            message.contains("os error"),
            "missing Windows OS error detail in: {message}"
        );
        assert!(
            !message.contains("OS error unavailable"),
            "Windows load failure lost its OS error detail: {message}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn component_collection_normalizes_posix_separators() {
        // The windows load() relies on this: a manifest-derived path with a
        // POSIX tail must come out with backslashes only, or LoadLibraryExW
        // rejects it with ERROR_MOD_NOT_FOUND.
        let mixed = Path::new(r"C:\runtime\lib/llama.dll");
        let normalized: std::path::PathBuf = mixed.components().collect();
        assert_eq!(normalized, Path::new(r"C:\runtime\lib\llama.dll"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unknown_windows_errors_report_os_error_zero() {
        let path = Path::new("mesh-llm-missing-native-runtime.dll");
        let message = format_load_error(path, &libloading::Error::LoadLibraryExWUnknown);

        assert!(message.contains("OS error 0"));
    }
}
