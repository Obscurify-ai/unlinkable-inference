//! An `AsyncWrite` that hands each write to a channel, so encrypted chunks can
//! be streamed to the network as they are produced.

use bytes::Bytes;
use futures::channel::mpsc::UnboundedSender;
use futures::AsyncWrite;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct ChannelWriter(pub Option<UnboundedSender<Bytes>>);

impl AsyncWrite for ChannelWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &self.0 {
            Some(tx) if tx.unbounded_send(Bytes::copy_from_slice(buf)).is_ok() => {
                Poll::Ready(Ok(buf.len()))
            }
            _ => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader went away"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.take();
        Poll::Ready(Ok(()))
    }
}

/// Write an indeterminate-length binary HTTP response (RFC 9292 §3.2)
/// piece by piece, so a streamed body can be sent before it ends.
pub mod bhttp_stream {
    fn varint(out: &mut Vec<u8>, v: u64) {
        if v < 1 << 6 {
            out.push(v as u8);
        } else if v < 1 << 14 {
            out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
        } else if v < 1 << 30 {
            out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
        } else {
            out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
        }
    }

    /// Framing indicator, status and header fields.
    pub fn response_head<'a>(status: u16, headers: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> Vec<u8> {
        let mut out = Vec::new();
        varint(&mut out, 3); // indeterminate-length response
        varint(&mut out, status as u64);
        for (name, value) in headers {
            varint(&mut out, name.len() as u64);
            out.extend_from_slice(name);
            varint(&mut out, value.len() as u64);
            out.extend_from_slice(value);
        }
        varint(&mut out, 0); // end of header section
        out
    }

    /// One body chunk. Must not be empty: a zero length ends the body.
    pub fn content_chunk(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 8);
        varint(&mut out, data.len() as u64);
        out.extend_from_slice(data);
        out
    }

    /// End of body, then an empty trailer section.
    pub fn end() -> Vec<u8> {
        vec![0, 0]
    }
}
