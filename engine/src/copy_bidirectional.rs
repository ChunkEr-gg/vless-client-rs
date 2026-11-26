// Forked from tokio's copy.rs and copy_bidirectional.rs.
//
// Changes:
// - Customizable buffer size
// - Read and write whenever there's a space
// - Circular buffer
// - Cooperative yielding via tokio's coop budget to prevent task starvation

use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::async_stream::AsyncStream;
use crate::util::allocate_vec;

const DEFAULT_BUF_SIZE: usize = 16384;
pub(crate) const MAX_COPY_BYTES_PER_POLL: usize = 1024 * 1024;

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    start_index: usize,
    cache_length: usize,
    size: usize,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    pub fn new(size: usize, need_initial_flush: bool) -> Self {
        let buf = allocate_vec(size);
        Self {
            read_done: false,
            need_flush: need_initial_flush,
            need_write_ping: false,
            start_index: 0,
            cache_length: 0,
            size,
            buf: buf.into_boxed_slice(),
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncStream + ?Sized,
        W: AsyncStream + ?Sized,
    {
        let coop = ready!(tokio::task::coop::poll_proceed(cx));
        // Initial output and an unfinished flush remain barriers across polls.
        if self.need_flush {
            ready!(writer.as_mut().poll_flush(cx))?;
            self.need_flush = false;
            coop.made_progress();
        }
        let mut copied = 0;

        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // Read as much as possible before writing. Some AsyncStream implementations
            // packetize each poll_write call individually, so this reduces the overhead.
            while !self.read_done && self.cache_length < self.size {
                let unused_start_index = (self.start_index + self.cache_length) % self.size;
                let unused_end_index_exclusive = if unused_start_index < self.start_index {
                    self.start_index
                } else {
                    self.size
                };

                let me = &mut *self;
                let mut buf =
                    ReadBuf::new(&mut me.buf[unused_start_index..unused_end_index_exclusive]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length += n;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                        break;
                    }
                }
            }

            if self.need_write_ping {
                if self.cache_length == 0 {
                    match writer.as_mut().poll_write_ping(cx) {
                        Poll::Ready(val) => {
                            let written = val?;
                            self.need_write_ping = false;
                            if written {
                                self.need_flush = true;
                                coop.made_progress();
                            }
                        }
                        Poll::Pending => {
                            write_pending = true;
                        }
                    }
                } else {
                    self.need_write_ping = false;
                }
            }

            while self.cache_length > 0 {
                let used_start_index = self.start_index;
                let used_end_index_exclusive =
                    (self.start_index + self.cache_length).min(self.size);

                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write(cx, &me.buf[used_start_index..used_end_index_exclusive])
                {
                    Poll::Ready(val) => {
                        let written = val?;
                        if written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            copied += written;
                            self.cache_length -= written;
                            if self.cache_length == 0 {
                                self.start_index = 0;
                            } else {
                                self.start_index = (self.start_index + written) % self.size;
                            }
                            self.need_flush = true;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            // Complete the current chunk rather than splitting a protocol-sized record.
            let quota_reached = copied >= MAX_COPY_BYTES_PER_POLL;
            if self.need_flush && (read_pending || write_pending || self.read_done || quota_reached)
            {
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
                coop.made_progress();
            }

            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            if read_pending || write_pending {
                return Poll::Pending;
            }
            if quota_reached {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown(Pin<Box<tokio::time::Sleep>>),
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    sleep_future: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<'a, A: AsyncStream + ?Sized, B: AsyncStream + ?Sized> CopyBidirectional<'a, A, B> {
    fn new(
        a: &'a mut A,
        b: &'a mut B,
        a_need_initial_flush: bool,
        b_need_initial_flush: bool,
        a_to_b_buf_size: usize,
        b_to_a_buf_size: usize,
    ) -> Self {
        let sleep_future = if a.supports_ping() || b.supports_ping() {
            Some(Box::pin(tokio::time::sleep(
                std::time::Duration::from_secs(60),
            )))
        } else {
            None
        };

        let a_to_b_buf_size = copy_buffer_size(a_to_b_buf_size, b);
        let b_to_a_buf_size = copy_buffer_size(b_to_a_buf_size, a);
        Self {
            a,
            b,
            a_buf: CopyBuffer::new(a_to_b_buf_size, b_need_initial_flush),
            b_buf: CopyBuffer::new(b_to_a_buf_size, a_need_initial_flush),
            a_to_b: TransferState::Running,
            b_to_a: TransferState::Running,
            sleep_future,
        }
    }
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(Box::pin(tokio::time::sleep(
                    crate::util::SHUTDOWN_TIMEOUT,
                )));
            }
            TransferState::ShuttingDown(deadline) => match w.as_mut().poll_shutdown(cx) {
                Poll::Ready(result) => {
                    result?;
                    *state = TransferState::Done;
                }
                Poll::Pending => {
                    ready!(deadline.as_mut().poll(cx));
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stream shutdown timed out",
                    )));
                }
            },
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
            sleep_future,
        } = &mut *self;

        if let Some(sleep) = sleep_future {
            let ping_fired = sleep.as_mut().poll(cx).is_ready();
            if ping_fired {
                a_buf.need_write_ping = b.supports_ping();
                b_buf.need_write_ping = a.supports_ping();
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
            }
        }

        let a_result = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_result = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        match (a_result, b_result) {
            (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            _ => Poll::Pending,
        }
    }
}

pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    CopyBidirectional::new(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        DEFAULT_BUF_SIZE,
        DEFAULT_BUF_SIZE,
    )
    .await
}

pub async fn copy_bidirectional_with_sizes<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
    a_to_b_buf_size: usize,
    b_to_a_buf_size: usize,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    CopyBidirectional::new(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        a_to_b_buf_size,
        b_to_a_buf_size,
    )
    .await
}

fn copy_buffer_size(requested: usize, writer: &(impl AsyncStream + ?Sized)) -> usize {
    match writer.preferred_write_size() {
        Some(preferred) => requested.min(preferred.get()),
        None => requested,
    }
}

#[cfg(test)]
pub(crate) mod tests;
