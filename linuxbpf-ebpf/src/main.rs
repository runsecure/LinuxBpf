// `#![no_std]`: this program never runs as a normal OS process, so it
// can't link the Rust standard library. The kernel loads its compiled
// bytecode directly into the in-kernel BPF virtual machine, where there's
// no libc, no heap allocator by default, no threads, no filesystem --
// none of the things `std` assumes exist. Only `core` (the
// std-independent basics: primitive types, `Option`/`Result`, slices,
// etc.) is available to this crate.
#![no_std]
// `#![no_main]`: skip Rust's usual single `fn main()` entry-point
// convention. A compiled BPF object doesn't have one "main" -- every
// function tagged with an attribute like `#[cgroup_skb]` (see
// ingress.rs/egress.rs below) becomes its own independent, separately
// loadable program with its own section in the output ELF file, and the
// kernel calls whichever one it was told to attach, once per packet, on
// its own schedule -- not once at process startup.
#![no_main]

// Each `mod` line below pulls in one sibling source file as part of this
// crate. Rust modules are just a namespacing/visibility mechanism here --
// at the BPF level there's no "module system" in the compiled output, all
// of this becomes one flat object file.
mod egress; // the `#[cgroup_skb]` program the kernel runs for outbound (egress) packets
mod filter; // the shared "is this packet allowed?" decision logic both programs call into
mod ingress; // the `#[cgroup_skb]` program the kernel runs for inbound (ingress) packets
mod maps; // declares the BPF maps: kernel-managed data structures both programs read from
mod reader; // adapts the real kernel packet context to a small, testable trait

// Only compile this panic handler into the real (non-`test`) build: under
// `cargo test`, this crate is compiled as an ordinary host binary/library
// with a normal standard-library panic handler already provided, and
// defining a second one would conflict with it.
#[cfg(not(test))]
// Every `no_std` binary must supply exactly one `#[panic_handler]`
// function: the thing the compiler wires up to run if `panic!()` (or an
// implicit check it inserts, like an array-bounds failure) is ever
// reached. Here it's just an infinite loop -- there's no terminal to
// print a message to and no OS process to exit from. In practice, the
// eBPF verifier statically proves every actual code path in this
// program's logic is safe (see `filter.rs`'s and `linuxbpf-common`'s
// comments for the lengths that took), so this loop is never expected to
// run; it exists only because the compiler requires *something* to be
// defined here.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
