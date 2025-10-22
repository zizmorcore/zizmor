//! A very minimal Git packet line ("pkt-line") implementation.
//!
//! This provides the bare minimum functionality needed to communicate
//! over Git's "smart" HTTP protocol, e.g. for efficiently listing remote
//! refs without cloning or using GitHub's REST API endpoints.
//!
//! More precisely, this module only implements the "v2" Git protocol.
//!
//! See: https://git-scm.com/docs/pack-protocol
//! See: https://git-scm.com/docs/protocol-common
//! See: https://git-scm.com/docs/protocol-v2

use thiserror::Error;

const LENGTH_PREFIX_LEN: usize = 4;
const MAX_DATA_LEN: usize = 65516;
const MAX_PKTLINE_LEN: usize = MAX_DATA_LEN + LENGTH_PREFIX_LEN;

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
    BadPacket { control: usize },
    /// Empty packet line.
    /// This means we received a `0004` packet line, which the server should not send.
    #[error("invalid packet line: empty")]
    Empty,
    /// Packet line data is too long.
    /// This means the data to be encoded/decoded exceeds the maximum allowed length.
    #[error("packet line data is too long: maximum is {MAX_DATA_LEN} bytes, got {actual} bytes")]
    DataTooLong { actual: usize },
}

/// Valid packets
pub(crate) enum Packet {
    Data(Vec<u8>),
    Flush,
    Delim,
}

impl Packet {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, PktLineError> {
        match self {
            Packet::Data(data) => {
                let len = data.len() + 4;
                let mut pkt = format!("{:04x}", len).into_bytes();
                if pkt.len() != 4 {
                    return Err(PktLineError::DataTooLong { actual: data.len() });
                }
                pkt.extend_from_slice(data);
                Ok(pkt)
            }
            Packet::Flush => Ok(b"0000".to_vec()),
            Packet::Delim => Ok(b"0001".to_vec()),
        }
    }

    pub(crate) fn decode(packet: &[u8]) -> Result<Self, PktLineError> {
        if packet.len() < LENGTH_PREFIX_LEN {
            return Err(PktLineError::FrameTooShort {
                actual: packet.len(),
            });
        }

        // Split the length and data apart.
        // We expect exactly 4 hex digits for the length prefix.
        let (length_bytes, data) = packet.split_at(4);
        let Ok(length_str) = str::from_utf8(length_bytes) else {
            return Err(PktLineError::BadLength {
                length: length_bytes.try_into().unwrap(),
            });
        };

        let Ok(length) = usize::from_str_radix(length_str, 16) else {
            return Err(PktLineError::BadLength {
                length: length_bytes.try_into().unwrap(),
            });
        };

        match length {
            0 => Ok(Packet::Flush),
            1 => Ok(Packet::Delim),
            2 | 3 => Err(PktLineError::BadPacket { control: length }),
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
                    Ok(Packet::Data(data[..data_len].to_vec()))
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

#[cfg(test)]
mod tests {
    use core::panic;

    use super::Packet;

    #[test]
    fn test_flush_packet() {
        let pkt = Packet::Flush;
        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded, b"0000");

        let decoded = Packet::decode(&encoded).unwrap();
        assert!(matches!(decoded, Packet::Flush));
    }

    #[test]
    fn test_delim_packet() {
        let pkt = Packet::Delim;
        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded, b"0001");

        let decoded = Packet::decode(&encoded).unwrap();
        assert!(matches!(decoded, Packet::Delim));
    }

    #[test]
    fn test_data_packet() {
        let data = b"hello, world!".to_vec();
        let pkt = Packet::Data(data.clone());
        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded, b"0011hello, world!");

        let Packet::Data(decoded) = Packet::decode(&encoded).unwrap() else {
            panic!("expected data packet");
        };
        assert_eq!(decoded, data);
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
            assert!(matches!(err, super::PktLineError::BadPacket { .. }));
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
