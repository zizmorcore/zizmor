//! A very minimal Git packet line ("pkt-line") implementation.
//!
//! This provides the bare minimum functionality needed to communicate
//! over Git's "smart" HTTP protocol, e.g. for efficiently listing remote
//! refs without cloning or using GitHub's REST API endpoints.
//!
//! Modules like [`lineref`](crate::github::lineref) build on top of this
//! to provide higher-level handling of specific responses.
//!
//! More precisely, this module only implements (a subset of) the "v2" Git protocol.
//!
//! See: https://git-scm.com/docs/pack-protocol
//! See: https://git-scm.com/docs/protocol-common
//! See: https://git-scm.com/docs/protocol-v2

use thiserror::Error;

const LENGTH_PREFIX_LEN: usize = 4;
const MAX_DATA_LEN: usize = 65516;

/// Errors that can occur while encoding or decoding pkt-lines.
#[derive(Debug, Error)]
pub(crate) enum PktLineError {
    /// Packet line frame is too short.
    /// This means we received less than 4 bytes when trying to read the length prefix.
    #[error(
        "packet line frame is too short: expected at least {LENGTH_PREFIX_LEN} bytes, got {actual} bytes"
    )]
    FrameTooShort { actual: usize },
    /// Invalid packet line length prefix.
    /// This means the first 4 bytes of the packet line were not valid hexadecimal digits.
    #[error("invalid packet line length: expected hex digits, got '{length:?}'")]
    BadLength { length: [u8; 4] },
    /// Packet line data is shorter than indicated by length prefix.
    /// This means the length prefix indicated more bytes than were actually present.
    #[error(
        "packet line data is too short: expected at least {expected} bytes, got {actual} bytes"
    )]
    DataTooShort { expected: usize, actual: usize },
    /// Invalid non-data packet.
    /// This means we received a control code that we don't recognize,
    /// i.e. something other than flush (`0000`) or delim (`0001`).
    #[error("invalid packet line: unexpected control code {control:04x}")]
    BadControl { control: usize },
    /// Empty packet line.
    /// This means we received a `0004` packet line, which the server should not send.
    #[error("invalid packet line: empty")]
    Empty,
    /// Packet line data is too long.
    /// This means the data to be encoded/decoded exceeds the maximum allowed length.
    #[error("packet line data is too long: maximum is {MAX_DATA_LEN} bytes, got {actual} bytes")]
    DataTooLong { actual: usize },
    /// In-band error.
    /// This happens when the server sends an us an `ERR` packet line,
    /// including a malformed one.
    #[error("in-band error: {message}")]
    InBandError { message: String },
    /// Unexpected control code.
    /// This means we received a control code that we didn't contextually expect.
    #[error("unexpected control code: {control}")]
    UnexpectedControl { control: usize },
}

/// Represents the data portion of a pkt-line data packet.
///
/// Invariant: the length of the data is at most [`MAX_DATA_LEN`].
#[derive(Copy, Clone)]
pub(crate) struct Data<'a> {
    inner: &'a [u8],
}

impl<'a> Data<'a> {
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    pub(crate) fn as_ref(&self) -> &'a [u8] {
        self.inner
    }
}

impl<'a> TryFrom<&'a [u8]> for Data<'a> {
    type Error = PktLineError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() > MAX_DATA_LEN {
            Err(PktLineError::DataTooLong {
                actual: value.len(),
            })
        } else {
            Ok(Data { inner: value })
        }
    }
}

/// Valid packets
pub(crate) enum Packet<'a> {
    Data(Data<'a>),
    Flush,
    Delim,
}

impl<'a> Packet<'a> {
    pub(crate) fn data(data: &'a [u8]) -> Result<Self, PktLineError> {
        Data::try_from(data).map(Self::Data)
    }

    pub(crate) fn encode(&self, dest: &mut Vec<u8>) -> Result<(), PktLineError> {
        match self {
            Packet::Data(data) => {
                let len = data.len() + 4;
                dest.extend_from_slice(&format!("{:04x}", len).into_bytes());
                dest.extend_from_slice(data.as_ref());
                Ok(())
            }
            Packet::Flush => {
                dest.extend_from_slice(b"0000");
                Ok(())
            }
            Packet::Delim => {
                dest.extend_from_slice(b"0001");
                Ok(())
            }
        }
    }

    /// Decode a single pkt-line packet from the start of the given byte slice.
    ///
    /// Returns the decoded packet, or an error if decoding failed.
    pub(crate) fn decode(packet: &'a [u8]) -> Result<Self, PktLineError> {
        if packet.len() < LENGTH_PREFIX_LEN {
            return Err(PktLineError::FrameTooShort {
                actual: packet.len(),
            });
        }

        // Split the length and data apart.
        // We expect exactly 4 hex digits for the length prefix.
        let (length_bytes, data) = packet.split_at(4);

        let length_bytes: [u8; 4] = length_bytes
            .try_into()
            .expect("impossible: length_bytes is 4 bytes");

        let Ok(length_str) = str::from_utf8(&length_bytes) else {
            return Err(PktLineError::BadLength {
                length: length_bytes,
            });
        };

        let Ok(length) = usize::from_str_radix(length_str, 16) else {
            return Err(PktLineError::BadLength {
                length: length_bytes,
            });
        };

        match length {
            0 => Ok(Packet::Flush),
            1 => Ok(Packet::Delim),
            2 | 3 => Err(PktLineError::BadControl { control: length }),
            4 => Err(PktLineError::Empty),
            _ => {
                let data_len = length - LENGTH_PREFIX_LEN;
                if data_len > MAX_DATA_LEN {
                    Err(PktLineError::DataTooLong { actual: data_len })
                } else if data.len() < data_len {
                    Err(PktLineError::DataTooShort {
                        expected: data_len,
                        actual: data.len(),
                    })
                } else {
                    let data = Data::try_from(&data[..data_len])?;

                    if data.as_ref().starts_with(b"ERR ") {
                        let message = String::from_utf8_lossy(&data.as_ref()[4..]).to_string();
                        Err(PktLineError::InBandError { message })
                    } else {
                        Ok(Packet::Data(data))
                    }
                }
            }
        }
    }

    pub(crate) fn length(&self) -> usize {
        match self {
            Packet::Data(data) => data.len() + LENGTH_PREFIX_LEN,
            Packet::Flush => LENGTH_PREFIX_LEN,
            Packet::Delim => LENGTH_PREFIX_LEN,
        }
    }
}

/// An iterator over pkt-line packets in a byte slice.
/// This will yield packets until the end of the slice is reached.
/// The user is responsible for assigning meaning to the sequence of packets,
/// including flush and delim packets.
pub(crate) struct PacketIterator<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> PacketIterator<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
}

impl<'a> Iterator for PacketIterator<'a> {
    type Item = Result<Packet<'a>, PktLineError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.data.len() {
            return None;
        }

        let remaining = &self.data[self.position..];
        match Packet::decode(remaining) {
            Ok(pkt) => {
                self.position += pkt.length();
                Some(Ok(pkt))
            }
            Err(err) => Some(Err(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use crate::github::pktline::{Data, MAX_DATA_LEN, Packet};

    #[test]
    fn test_data_size_invariant() {
        let data = vec![0u8; MAX_DATA_LEN + 1];
        let Err(err) = Data::try_from(data.as_slice()) else {
            panic!("expected error for data exceeding max length");
        };
        assert!(matches!(err, super::PktLineError::DataTooLong { .. }));
    }

    #[test]
    fn test_flush_packet() {
        let mut encoded = vec![];
        let pkt = Packet::Flush;
        pkt.encode(&mut encoded).unwrap();
        assert_eq!(encoded, b"0000");

        let decoded = Packet::decode(&encoded).unwrap();
        assert!(matches!(decoded, Packet::Flush));
    }

    #[test]
    fn test_delim_packet() {
        let mut encoded = vec![];
        let pkt = Packet::Delim;
        pkt.encode(&mut encoded).unwrap();
        assert_eq!(encoded, b"0001");

        let decoded = Packet::decode(&encoded).unwrap();
        assert!(matches!(decoded, Packet::Delim));
    }

    #[test]
    fn test_data_packet() {
        let mut encoded = vec![];
        let data = Data::try_from(b"hello, world!".as_slice()).unwrap();
        let pkt = Packet::Data(data);
        pkt.encode(&mut encoded).unwrap();
        assert_eq!(encoded, b"0011hello, world!");

        let Packet::Data(decoded) = Packet::decode(&encoded).unwrap() else {
            panic!("expected data packet");
        };
        assert_eq!(decoded.as_ref(), data.as_ref());
    }

    #[test]
    fn test_error_packet() {
        let mut encoded = vec![];
        let error_message = Data::try_from(b"ERR something went wrong".as_slice()).unwrap();
        let pkt = Packet::Data(error_message);
        pkt.encode(&mut encoded).unwrap();
        assert_eq!(encoded, b"001cERR something went wrong");

        let Err(err) = Packet::decode(&encoded) else {
            panic!("expected error packet");
        };
        assert!(matches!(err, super::PktLineError::InBandError { .. }));
    }

    #[test]
    fn test_decode_invalid_cases() {
        // Invalid framings.
        for case in &[
            b"".as_slice(),
            b"0".as_slice(),
            b"00".as_slice(),
            b"000".as_slice(),
        ] {
            let Err(err) = Packet::decode(case) else {
                panic!("expected error for case: {:?}", case);
            };
            assert!(matches!(err, super::PktLineError::FrameTooShort { .. }));
        }

        // Invalid length prefixes (not hex/invalid UTF8).
        for case in &[b"zzzz", b"\x00\x00\x00\x00", b"\xf0\x28\x8c\xbc"] {
            let Err(err) = Packet::decode(*case) else {
                panic!("expected error for case: {:?}", case);
            };
            assert!(matches!(err, super::PktLineError::BadLength { .. }));
        }

        // Bad packets (unknown control codes).
        for case in &[b"0002", b"0003"] {
            let Err(err) = Packet::decode(*case) else {
                panic!("expected error for case: {:?}", case);
            };
            assert!(matches!(err, super::PktLineError::BadControl { .. }));
        }

        // Too long (length field exceeds max).
        let Err(err) = Packet::decode(b"ffffhello") else {
            panic!("expected error for too long case");
        };
        assert!(matches!(err, super::PktLineError::DataTooLong { .. }));

        // Too short (data shorter than length field).
        let Err(err) = Packet::decode(b"0008hi") else {
            panic!("expected error for too short case");
        };
        assert!(matches!(err, super::PktLineError::DataTooShort { .. }));
    }
}
