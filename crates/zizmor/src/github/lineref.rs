//! Direct "line ref" parsing for Git references.
//!
//! This builds on top of the pkt-line protocol implementation in
//! [`pktline`](crate::github::pktline) to parse Git references
//! directly from a Git server's reference list advertisement
//! (over the "smart" HTTP protocol + Git v2 protocol).

use thiserror::Error;

use crate::{github::pktline, utils::once::static_regex};

// A regex pattern for parsing Git line refs.
//
// This only matches the subset of line refs that we expect to see
// in practice: those with an object ID, a ref name, and optionally
// a peeled object ID.
static_regex!(
    LINE_REF_PATTERN,
    r#"(?x)                    # verbose mode
        ^                          # start of string
        (?P<obj_id>[0-9a-f]{40} )  # object ID
        (?-x: )                    # single space (temporarily disable verbose)
        (?P<ref_name>\S+)          # ref name
        (                          # start optional peeled group
          (?-x: )                  # space
          peeled:                  # 'peeled:' label
          (?P<peeled_obj_id>
            [0-9a-f]{40}           # peeled object ID
          )
        )?                         # end optional peeled group
        $                          # end of string
        "#
);

#[derive(Debug, Error)]
pub(crate) enum LineRefError {
    /// Packet decoding error.
    #[error("Git pkt-line decoding error")]
    Packet(#[from] pktline::PktLineError),
    /// Invalid reference encoding.
    /// This means we received data that was not valid UTF-8.
    #[error("invalid reference: not valid UTF-8")]
    BadRefEncoding(#[from] std::str::Utf8Error),
    /// Malformed line ref.
    #[error("malformed line ref: {line}")]
    BadLine { line: String },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LineRef<'a> {
    /// The object ID (SHA-1 or SHA-256) that the ref points to.
    pub(crate) obj_id: &'a str,
    /// The full ref name, e.g. `refs/heads/main` or `refs/tags/v1.0.0`.
    pub(crate) ref_name: &'a str,
    /// The peeled object ID, if the ref has a `peeled` attribute.
    pub(crate) peeled_obj_id: Option<&'a str>,
}

impl<'a> LineRef<'a> {
    /// Turn a decoded pkt-line data packet into a `LineRef`.
    pub(crate) fn parse(data: pktline::Data<'a>) -> Result<Self, LineRefError> {
        // From Git's protocol-v2:
        //
        // output = *ref
        //   flush-pkt
        // obj-id-or-unborn = (obj-id | "unborn")
        // ref = PKT-LINE(obj-id-or-unborn SP refname *(SP ref-attribute) LF)
        // ref-attribute = (symref | peeled)
        // symref = "symref-target:" symref-target
        // peeled = "peeled:" obj-id
        //
        // Where obj-id and refname are defined in protocol-common as:
        //
        // NUL       =  %x00
        // zero-id   =  40*"0"
        // obj-id    =  40*(HEXDIGIT)
        // refname  =  "HEAD"
        // refname /=  "refs/" <see discussion below>
        //
        // We send `peel` as an argument, so we expect the `peeled:obj-id`
        // attribute to be present for annotated tags.

        // These packets should be UTF-8 encoded strings.
        let mut line = str::from_utf8(data.as_ref()).map_err(LineRefError::BadRefEncoding)?;

        // We expect a LF, but protocol-common says we shouldn't
        // complain if it's missing.
        if line.ends_with("\n") {
            line = &line[..line.len() - 1];
        }

        let captures = LINE_REF_PATTERN
            .captures(line)
            .ok_or_else(|| LineRefError::BadLine {
                line: line.to_string(),
            })?;

        Ok(Self {
            obj_id: captures
                .name("obj_id")
                .expect("internal error: mandatory capture missing from lineref pattern")
                .as_str(),
            ref_name: captures
                .name("ref_name")
                .expect("internal error: mandatory capture missing from lineref pattern")
                .as_str(),
            peeled_obj_id: captures.name("peeled_obj_id").map(|m| m.as_str()),
        })
    }
}

/// An iterator over Git line refs from a pkt-line data stream.
///
/// This wraps a [`pktline::PacketIterator`] and yields parsed [`LineRef`]s.
pub(crate) struct LineRefIterator<'a> {
    inner: pktline::PacketIterator<'a>,
}

impl<'a> LineRefIterator<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            inner: pktline::PacketIterator::new(data),
        }
    }
}

impl<'a> Iterator for LineRefIterator<'a> {
    type Item = Result<LineRef<'a>, LineRefError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(pktline::Packet::Data(data)) => Some(LineRef::parse(data)),
            Ok(pktline::Packet::Flush) => None,
            // We don't expect any non-flush control packets in the
            // reference listing response.
            Ok(pktline::Packet::Delim) => Some(Err(LineRefError::Packet(
                pktline::PktLineError::UnexpectedControl { control: 1 },
            ))),
            Err(e) => Some(Err(LineRefError::Packet(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// From:
    /// ```
    /// curl 'https://github.com/woodruffw-experiments/zizmor-recursive-tags.git/git-upload-pack' \
    ///     -d $'0014command=ls-refs\n00010009peel\n0000' \
    ///     -H 'Git-Protocol: version=2'
    /// ```
    #[test]
    fn test_iterator() {
        let resp = r#"0032ac7cfa9fb7b5d6c417847e49e375aae20819a06f HEAD
003dac7cfa9fb7b5d6c417847e49e375aae20819a06f refs/heads/main
003e3e793ac5aba04cf8157e52e796de2d808f800039 refs/pull/1/head
006a1accca34bff60347d96faaf713d328ca1250d37b refs/tags/v1 peeled:3fdd4fca8fc76b254cefefca92381c41b28d1f0d
006cbcb36f3d551340e11b88c376e74e8ae77fc6cf0b refs/tags/v1.0 peeled:3fdd4fca8fc76b254cefefca92381c41b28d1f0d
006e06f9d47abf340b709b412900a7b3ce33557d32b5 refs/tags/v1.0.0 peeled:3fdd4fca8fc76b254cefefca92381c41b28d1f0d
0000
"#;

        let refs: Result<Vec<_>, _> = LineRefIterator::new(resp.as_bytes()).collect();
        let refs = refs.unwrap();

        assert_eq!(
            refs,
            &[
                LineRef {
                    obj_id: "ac7cfa9fb7b5d6c417847e49e375aae20819a06f",
                    ref_name: "HEAD",
                    peeled_obj_id: None,
                },
                LineRef {
                    obj_id: "ac7cfa9fb7b5d6c417847e49e375aae20819a06f",
                    ref_name: "refs/heads/main",
                    peeled_obj_id: None,
                },
                LineRef {
                    obj_id: "3e793ac5aba04cf8157e52e796de2d808f800039",
                    ref_name: "refs/pull/1/head",
                    peeled_obj_id: None,
                },
                LineRef {
                    obj_id: "1accca34bff60347d96faaf713d328ca1250d37b",
                    ref_name: "refs/tags/v1",
                    peeled_obj_id: Some("3fdd4fca8fc76b254cefefca92381c41b28d1f0d"),
                },
                LineRef {
                    obj_id: "bcb36f3d551340e11b88c376e74e8ae77fc6cf0b",
                    ref_name: "refs/tags/v1.0",
                    peeled_obj_id: Some("3fdd4fca8fc76b254cefefca92381c41b28d1f0d"),
                },
                LineRef {
                    obj_id: "06f9d47abf340b709b412900a7b3ce33557d32b5",
                    ref_name: "refs/tags/v1.0.0",
                    peeled_obj_id: Some("3fdd4fca8fc76b254cefefca92381c41b28d1f0d"),
                },
            ]
        )
    }
}
