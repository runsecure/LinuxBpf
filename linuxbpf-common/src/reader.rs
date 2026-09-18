//! Abstracts "read bytes from a packet" so `ip::parse` doesn't have to be
//! written directly against `aya_ebpf::programs::SkBuffContext`. The real
//! eBPF crate implements this trait as a thin wrapper around
//! `SkBuffContext::load`/`load_bytes`; tests implement it over a plain
//! `&[u8]` buffer so the parsing logic can be exercised without a kernel.

// A Rust `trait` is an interface: a set of method signatures any type can
// promise to implement. Code written against `PacketReader` (like
// `ip::parse`) doesn't know or care *which* concrete type it's given at
// any particular call site -- only that whatever it is has these four
// methods. This is what makes the exact same parsing code run both inside
// the kernel (against a real packet) and inside an ordinary `cargo test`
// process (against a fake one) -- see the two `impl` blocks below.
pub trait PacketReader {
    /// EtherType of the packet, in host byte order (e.g. `0x0800` for
    /// IPv4). On a real `__sk_buff` this field is network-byte-order and
    /// must be converted; implementations are responsible for that.
    fn ether_type(&self) -> u16;

    /// Reads a `Copy` value of type `T` starting at `offset`. Must fail
    /// (`Err(())`) rather than panic or read out of bounds if `offset +
    /// size_of::<T>()` exceeds the available data.
    // `T: Copy` restricts what types this can be called with to those
    // that are safe to duplicate by copying their raw bytes (no
    // destructors, no ownership subtleties) -- exactly the kind of type
    // that's safe to conjure directly out of a packet's raw bytes, which
    // is what every real implementation of this method does under the
    // hood.
    fn load<T: Copy>(&self, offset: usize) -> Result<T, ()>;

    /// Reads up to `dst.len()` bytes starting at `offset` into `dst`,
    /// returning the number of bytes actually read (which may be less than
    /// `dst.len()` if the packet is shorter).
    fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, ()>;

    /// Total packet length.
    fn len(&self) -> u32;

    /// Reads exactly `dst.len()` bytes starting at `offset`, writing
    /// directly into `dst` -- unlike `load_bytes`, this never partially
    /// fills `dst`: it's all-or-nothing, failing if fewer than `dst.len()`
    /// bytes remain in the packet.
    ///
    /// This exists (rather than just using `load_bytes` with a
    /// fixed-size destination) because the real `SkBuffContext::load_bytes`
    /// computes `self.len() - offset` internally to clamp its read to
    /// what's actually available, and the eBPF verifier rejects the
    /// resulting kernel helper call outright if it can't prove that
    /// clamped length is nonzero ("invalid zero-sized read") -- which it
    /// can't, purely from an offset's own value range. Requesting a fixed,
    /// literal-constant length instead (never computed as a `min()` against
    /// a runtime value) sidesteps that: the call either succeeds with
    /// exactly that many bytes, or fails outright, both of which are
    /// ordinary runtime outcomes this trait already models with `Result`.
    fn load_bytes_fixed(&self, offset: usize, dst: &mut [u8]) -> Result<(), ()>;
}

/// Test-only `PacketReader` backed by an in-memory buffer, so
/// `ip::parse` can be unit tested with hand-built packets instead of a
/// real `__sk_buff`.
// Only compiled while running this crate's own tests -- there's no reason
// for either the real kernel build or the userspace build to ever see
// this type.
#[cfg(test)]
pub struct SliceReader<'a> {
    pub ether_type: u16,
    // A borrowed slice of whatever fake "packet bytes" a test built (see
    // `ip.rs`'s `bytes_of` helper, for example) -- `SliceReader` doesn't
    // own the data, just refers to it, which is why it needs the `'a`
    // lifetime parameter: this struct can't outlive the buffer it points
    // into.
    pub data: &'a [u8],
}

#[cfg(test)]
// This block is the entire "fake packet" implementation: every method
// below reimplements what a real kernel read would do, but purely in
// terms of ordinary slice operations on `self.data` -- no kernel, no
// helper calls, no `unsafe` kernel FFI at all (only one small, contained
// `unsafe` block, explained below, for a reinterpretation that's
// otherwise identical to what a real packet read does).
impl<'a> PacketReader for SliceReader<'a> {
    fn ether_type(&self) -> u16 {
        self.ether_type
    }

    fn load<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        let size = core::mem::size_of::<T>();
        // `checked_add` returns `None` instead of silently wrapping
        // around on overflow (which could otherwise turn a huge,
        // out-of-range `offset` into a small, seemingly-valid one) --
        // `.ok_or(())?` turns that `None` into this function's own
        // `Err(())` and returns early.
        let end = offset.checked_add(size).ok_or(())?;
        // `self.data.get(offset..end)`: a bounds-checked slice of the
        // buffer -- returns `None` (turned into `Err(())` the same way)
        // if `end` runs past the actual end of `self.data`, rather than
        // panicking the way plain `self.data[offset..end]` indexing
        // would.
        let bytes = self.data.get(offset..end).ok_or(())?;
        // SAFETY: `bytes` is exactly `size_of::<T>()` bytes long and `T:
        // Copy`, so any bit pattern is a valid `T`; read unaligned since
        // `offset` need not satisfy `T`'s natural alignment.
        //
        // This is the one line in this whole "fake" implementation that
        // mirrors what a *real* packet read fundamentally has to do: take
        // some raw bytes and reinterpret them as a typed value, without
        // Rust's normal type system being able to check that the bytes
        // actually form a valid instance of that type. `read_unaligned`
        // (as opposed to plain `*const T` dereferencing) additionally
        // tolerates `bytes.as_ptr()` not being aligned the way `T` would
        // normally require -- packet header offsets have no reason to
        // land on convenient alignment boundaries.
        Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) })
    }

    fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, ()> {
        let end = offset.checked_add(dst.len()).ok_or(())?;
        let bytes = self.data.get(offset..end).ok_or(())?;
        // Copy as many bytes as are actually available (which, given the
        // bounds check just above, is always exactly `bytes.len()` here)
        // into the front of `dst`, and report how many that was --
        // mirroring `SkBuffContext::load_bytes`'s "clamp to what's
        // available" behavior.
        dst[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    fn len(&self) -> u32 {
        self.data.len() as u32
    }

    fn load_bytes_fixed(&self, offset: usize, dst: &mut [u8]) -> Result<(), ()> {
        let end = offset.checked_add(dst.len()).ok_or(())?;
        let bytes = self.data.get(offset..end).ok_or(())?;
        // Unlike `load_bytes` above, this is genuinely all-or-nothing:
        // reaching this line already means exactly `dst.len()` bytes were
        // available (the bounds check on the line above would have
        // failed and returned `Err(())` otherwise), so the copy always
        // fills the whole destination.
        dst.copy_from_slice(bytes);
        Ok(())
    }
}
