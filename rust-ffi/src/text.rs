//! Strings crossing the C boundary.

use std::ffi::c_char;

/// An owned, NUL-terminated UTF-8 string lent to C. The pointer and length
/// stay valid as long as the owner lives.
///
/// Text with an interior NUL is kept whole: C callers that rely on the
/// terminator see a prefix, callers that take the length see all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CText(Box<[u8]>);

impl CText {
    pub fn new(text: &str) -> Self {
        let mut bytes = Vec::with_capacity(text.len() + 1);
        bytes.extend_from_slice(text.as_bytes());
        bytes.push(0);
        Self(bytes.into_boxed_slice())
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }

    /// Length in bytes, without the terminator.
    pub fn len(&self) -> usize {
        self.0.len() - 1
    }

    #[cfg(test)]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0[..self.len()]).expect("built from a str")
    }
}

/// Decode host bytes as UTF-8, replacing invalid sequences.
pub(crate) fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminates_and_measures_without_the_nul() {
        let text = CText::new("héllo");
        assert_eq!(text.len(), 6);
        assert_eq!(text.as_str(), "héllo");
        let terminator = text.0.last().copied();
        assert_eq!(terminator, Some(0));
    }

    #[test]
    fn replaces_invalid_utf8() {
        assert_eq!(lossy_text(b"a\xffb"), "a\u{fffd}b");
    }
}
