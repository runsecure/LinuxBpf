//! Thin adapter implementing `linuxbpf_common::reader::PacketReader` over a
//! real `SkBuffContext`, so `linuxbpf_common::ip::parse` (and the rest of
//! `filter.rs`) can be written once against the trait and shared with the
//! native unit tests in `linuxbpf-common`.

use aya_ebpf::programs::SkBuffContext;
use linuxbpf_common::reader::PacketReader;

// A one-field tuple struct that just wraps a reference to the real kernel
// packet context. It exists purely so `impl PacketReader for SkbReader`
// below can be written -- Rust doesn't allow implementing a trait
// directly for a type (`SkBuffContext`) defined in a different crate
// (`aya_ebpf`), so this local wrapper type is the standard way around
// that rule.
pub struct SkbReader<'a>(pub &'a SkBuffContext);

// This block is the entire "bridge" between the generic, testable parsing
// logic in `linuxbpf-common` and the real kernel packet API: every method
// here just forwards to the equivalent real `SkBuffContext` method (or, in
// one case, to a raw kernel helper call), translating error types along
// the way.
impl PacketReader for SkbReader<'_> {
    fn ether_type(&self) -> u16 {
        // __sk_buff.protocol is the EtherType in network byte order;
        // convert to host order for the human-readable constants in
        // `linuxbpf_common::ip`.
        //
        // `self.0` reaches through the wrapper to the real
        // `&SkBuffContext`; `.skb` is its embedded low-level accessor
        // struct; `.protocol()` reads the raw `__sk_buff.protocol` field.
        // It comes back as a `u32`, so `as u16` truncates it to the
        // 16-bit EtherType value it actually represents, and
        // `u16::from_be` swaps its byte order from network (big-endian)
        // to whatever this CPU's native order is, so callers can compare
        // it against ordinary human-readable constants like `0x0800`.
        u16::from_be(self.0.skb.protocol() as u16)
    }

    fn load<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        // Delegates straight to `SkBuffContext::load`, which does a
        // bounds-checked, verifier-provable read of `size_of::<T>()`
        // bytes starting at `offset` in the packet, returning that many
        // bytes reinterpreted as a `T`. Its real error type is a raw
        // kernel `c_long` error code; `.map_err(|_| ())` throws that
        // detail away and collapses it to the trait's plain `Err(())`,
        // since none of the calling code needs to distinguish *why* a
        // read failed, only that it did.
        self.0.load(offset).map_err(|_| ())
    }

    fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, ()> {
        // Same pattern as `load` above: forward to the real method, throw
        // away the specific kernel error code. `SkBuffContext::load_bytes`
        // copies up to `dst.len()` bytes into `dst`, clamped to however
        // much of the packet actually remains past `offset`, and returns
        // how many bytes it actually copied.
        self.0.load_bytes(offset, dst).map_err(|_| ())
    }

    fn len(&self) -> u32 {
        // Total packet length, straight from the kernel context -- no
        // translation needed since the trait's return type already
        // matches.
        self.0.len()
    }

    fn load_bytes_fixed(&self, offset: usize, dst: &mut [u8]) -> Result<(), ()> {
        // Bypasses `SkBuffContext::load_bytes`'s convenience clamping
        // (`min(dst.len(), self.len() - offset)`) by calling the raw
        // helper directly with `dst.len()` -- a literal, never-zero
        // length -- so the kernel verifier never has to prove a
        // `min()`-derived length is nonzero. See the doc comment on
        // `PacketReader::load_bytes_fixed`.
        //
        // SAFETY: `self.0.skb.skb` is the context's own valid `__sk_buff`
        // pointer; `dst` is a valid, appropriately-sized destination the
        // caller owns for the duration of this call.
        //
        // `unsafe` is required here because `bpf_skb_load_bytes` is a raw
        // FFI-style binding straight to the kernel's helper-call
        // mechanism -- Rust can't verify on its own that the pointer
        // arguments are valid, so calling it is an explicit promise from
        // this code (backed by the `SAFETY` reasoning above) that they
        // are.
        let ret = unsafe {
            aya_ebpf::helpers::bpf_skb_load_bytes(
                // `self.0.skb.skb`: two layers of wrapper to reach the
                // actual raw `*mut __sk_buff` pointer (`SkbReader` wraps
                // `&SkBuffContext`, which itself wraps a `skb: SkBuff`
                // accessor struct, whose own `skb` field is the real
                // pointer). `.cast()` converts its pointer type to
                // whatever the helper function's `skb` parameter expects.
                self.0.skb.skb.cast(),
                // Kernel helpers take plain `u32` offsets/lengths, not
                // `usize` -- this codebase's own types use `usize`
                // (Rust's normal indexing type) throughout, so it's
                // narrowed here at the FFI boundary.
                offset as u32,
                // Where to write the bytes read: a raw mutable pointer to
                // the start of the caller's `dst` buffer.
                dst.as_mut_ptr().cast(),
                // Exactly how many bytes to read -- always `dst.len()`,
                // never a value derived from the packet's own remaining
                // length, which is the whole point of this function (see
                // its doc comment on the trait).
                dst.len() as u32,
            )
        };
        // Kernel helper-call convention: `0` means success, anything else
        // is a (kernel-defined) error code. Translate that into the
        // trait's plain `Result<(), ()>`.
        if ret == 0 { Ok(()) } else { Err(()) }
    }
}
