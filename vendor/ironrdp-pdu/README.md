# IronRDP PDU

RDP PDU encoding and decoding library.

- [Overview of encoding and decoding traits](#overview-of-encoding-and-decoding-traits)
- [Difference between `WriteBuf` and `WriteCursor`](#difference-between-writebuf-and-writecursor)
- [Difference between `WriteBuf` and `Vec<u8>`](#difference-between-writebuf-and-vecu8)
- [Most PDUs are "plain old data" structures with public fields](#most-pdus-are-plain-old-data-structures-with-public-fields)
- [Enumeration-like types should allow resilient parsing](#enumeration-like-types-should-allow-resilient-parsing)
- [On bit flags](#on-bit-flags)

## Overview of encoding and decoding traits

It’s important for `Encode` to be object-safe in order to enable patterns such as the one
found in `ironrdp-svc`:

```rust
pub trait SvcProcessor {
    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<Box<dyn Encode>>>;
}
```

(The actual trait is a bit more complicated, but this gives the rough idea.)

TODO: elaborate this section

## Difference between `WriteBuf` and `WriteCursor`

`WriteCursor` is a wrapper around `&mut [u8]` and its purpose is to:

- Provide convenient methods such as `write_u8`, `write_u16`, `write_u16_be`, etc.
- Guarantee syscall-free, infallible write access to a continuous slice of memory.
- Keep track of the number of bytes written.
- Allow backtracking to override a value previously written or skipped.
- Be `no-std` and `no-alloc` friendly, which `std::io::Cursor` is not as of today.

The underlying storage could be abstracted over, but it’s deliberately hardcoded to `&mut [u8]`
so traits such as `Encode` using `WriteCursor` in their associated methods are object-safe.

`WriteBuf` is used in APIs where the required space cannot be known in advance. For instance,
`ironrdp_connector::Sequence::step` is taking `&mut WriteBuf` instead of `&mut
WriteCursor` because it’s unlikely the user knows exactly how much space is required to encode a
specific response before actually processing the input payload, and as such there is no easy way
to communicate the caller how much space is required before calling the function.

Consider this piece of code:

```rust
fn process(&mut self, payload: &[u8], output: &mut WriteBuf) -> PduResult<()> {
    let server_request: ServerRequest = ironrdp_pdu::decode(payload)?;

    match server_request.order {
        ServerOrder::DoThis => {
            // do this
            let response = DoThisResponse { /* … */ };

            // buffer is grown, or not, as appropriate, and `DoThisResponse` is encoded in the "unfilled" region
            ironrdp_pdu::encode_buf(response, output)?;
        }
        ServerOrder::DoThat => {
            // do that
            let response = DoThatResponse { /* … */ };

            // same as above
            ironrdp_pdu::encode_buf(response, output)?;
        }
    }

    Ok(())
}
```

Methods such as `write_u8` are overlapping with the `WriteCursor` API, but it’s mostly for
convenience if one needs to manually write something in an ad-hoc fashion, and using `WriteCursor`
is preferred in order to write `no-std` and `no-alloc` friendly code.

## Difference between `WriteBuf` and `Vec<u8>`

`WriteBuf` roles include:

- Maintaining a non-trivial piece of initialized memory consistently, all while ensuring that the
  internal `Vec<u8>` doesn't grow excessively large in memory throughout the program's
  execution. Keeping a piece of initialized memory around is useful to amortize the initialization
  cost of `Vec::resize` when building a `WriteCursor` (which requires a mutable slice of
  initialized memory, `&mut [u8]`).

- Keep track of the filled region in order to easily write multiple items sequentially within the
  same buffer.

`WriteCursor`, in essence, is a helper for this kind of code:

```rust
pub fn encode_buf<T: Encode + ?Sized>(pdu: &T, buf: &mut Vec<u8>, filled_len: usize) -> PduResult<usize> {
    let pdu_size = pdu.size();

    // Resize the buffer, making sure there is enough space to fit the serialized PDU
    if buf.len() < pdu_size {
        buf.resize(filled_len + pdu_size, 0);
    }

    // Proceed to actually serialize the PDU into the buffer…
    let mut cursor = WriteCursor::new(&mut buf[filled_len..]);
    encode_cursor(pdu, &mut cursor)?;

    let written = cursor.pos();

    Ok(written)
}

fn somewhere_else() -> PduResult<()> {
    let mut state_machine = /* … */;
    let mut buf = Vec::new();
    let mut filled_len;

    while !state_machine.is_terminal() {
        let pdus = state_machine.step();

        filled_len = 0;
        buf.shrink_to(16384); // Maintain up to 16 kib around

        for pdu in pdus {
            filled_len += encode_buf(&pdu, &mut buf, filled_len)?;
        }

        let filled = &buf[..filled_len];

        // Do something with `filled`
    }
}
```

Observe that this code, which relies on `Vec<u8>`, demands extra bookkeeping for the filled region
and a cautious approach when clearing and resizing it.

In comparison, the same code using `WriteBuf` looks like this:

```rust
pub fn encode_buf<T: Encode + ?Sized>(pdu: &T, buf: &mut WriteBuf) -> PduResult<usize> {
    let pdu_size = pdu.size();

    let dst = buf.unfilled_to(pdu_size);

    let mut cursor = WriteCursor::new(dst);
    encode_cursor(pdu, &mut cursor)?;

    let written = cursor.pos();
    buf.advance(written);

    Ok(written)
}

fn somewhere_else() -> PduResult<()> {
    let mut state_machine = /* … */;
    let mut buf = WriteBuf::new();

    while !state_machine.is_terminal() {
        let pdus = state_machine.step();

        buf.clear();

        for pdu in pdus {
            encode_buf(&pdu, &mut buf)?;
        }

        let filled = buf.filled();

        // Do something with `filled`
    }
}
```

A big enough mutable slice of the unfilled region is retrieved by using the `unfilled_to` helper
method (allocating more memory as necessary), a `WriteCursor` wrapping this slice is created and
used to actually encode the PDU. The filled region cursor of the `WriteBuf` is moved forward so that
the `filled` method returns the right region, and subsequent calls to `encode_buf` do not override
it until `clear` is called.

## Most PDUs are "plain old data" structures with public fields

In general, it is desirable for library users to be able to manipulate the fields directly because:

- One can deconstruct the types using pattern matching
- One can construct the type using a [field struct expression][1] (which is arguably more readable
  than a `new` method taking tons of parameters, and less boilerplate than a builder)
- One can use the [struct (functional) update syntax][2]
- One can move fields out of the struct without us having to add additional `into_xxx` API for each
  combination
- One can mutably borrow multiple fields of the struct at the same time (a getter will cause the
  entire struct to be considered borrowed by the borrow checker)

Keeping the fields private is opting out of all of this and making the API stiffer. Of course,
all of this applies because for most PDU structs there is no important invariants to uphold: they
are mostly dumb data holders or "plain old data structures" with no particular logic to run at
construction or destruction time. The story is not the same for objects with business logic (which
are mostly not part of `ironrdp-pdu`)

When hiding some fields is really required, one of the following approach is suggested:
- a "[Builder Lite][3]" pattern,
- a "[Init Struct][4]" pattern, or
- a standard handcrafted Builder Pattern

[1]: https://doc.rust-lang.org/reference/expressions/struct-expr.html#field-struct-expression
[2]: https://doc.rust-lang.org/reference/expressions/struct-expr.html#functional-update-syntax
[3]: https://matklad.github.io/2022/05/29/builder-lite.html
[4]: https://xaeroxe.github.io/init-struct-pattern/

## Enumeration-like types should allow resilient parsing

The **TL;DR** is that enums in Rust should not be used when parsing resilience is required.

Network protocols are generally designed with forward and backward compatibility in mind. Items
like status codes, error codes, and other enumeration-like types may later get extended to include
new values. Additionally, it's not uncommon for different implementations of the same protocol to
disagree with each other. Some implementations may exhibit a bug, inserting an unexpected value,
while others may intentionally extend the original protocol with a custom value.

Therefore, implementations of such protocols should decode these into a more flexible data type
that can accommodate a broader range of values, even when working with a language like Rust. As
long as the unknown value is not critical and can be handled gracefully, the implementation should
make every effort not to fail, especially during parsing.

For example, let’s consider the following `enum` in Rust:

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyNetworkCode {
    FirstValue = 0,
    SecondValue = 1,
}
```

This type cannot be used to hold new values that may be added to the protocol in the future. Thus,
it is not a suitable option.

Many Rust developers will instinctively write the following instead:

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyNetworkCode {
    FirstValue = 0,
    SecondValue = 1,
    // Fallback variant
    Unknown(u32),
}
```

This type can indeed hold additional values in its fallback variant, and the implementation can
remain compatible with future protocol versions as desired.

However, this solution is not without its issues. There is a hard to catch forward-compatibility
hazard at the library level: when a new value, such as `ThirdValue = 2`, is added to the enum, the
`Unknown` variant for this value will no longer be emitted by the library (the library does not
construct and return the value anymore). This can lead to _silent_ failures in downstream code that
relies on matching `Unknown` to handle the previously unknown value.

For instance:

```rust
// Library code

impl MyNetworkCode {
    fn parse_network_code(value: u32) -> MyNetworkCode {
        match value {
            0 => MyNetworkCode::FirstValue,
            1 => MyNetworkCode::SecondValue,
            _ => MyNetworkCode::Unknown(value),
        }
    }
}

// User code

fn handle_network_code(reader: /* … */) {
    let value = reader.read_u32();
    let code = MyNetworkCode::from_u32(value);

    if code == MyNetworkCode::Unknown(2) {
        // The library doesn’t know about this value yet, but we need to handle it because […]
    }
}
```

Once the library is updated to handle the third value:

```rust
// Library code

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyNetworkCode {
    FirstValue = 0,
    SecondValue = 1,
    ThirdValue = 2, // NEW
    Unknown(u32),
}

impl MyNetworkCode {
    fn parse_network_code(value: u32) -> MyNetworkCode {
        match value {
            0 => MyNetworkCode::FirstValue,
            1 => MyNetworkCode::SecondValue,
            2 => MyNetworkCode::ThirdValue, // NEW
            _ => MyNetworkCode::Unknown(value), // This branch is not entered anymore when value = 2
        }
    }
}

// User code (unchanged)

fn handle_network_code(reader: /* … */) {
    let value = reader.read_u32();
    let code = MyNetworkCode::from_u32(value);

    if code == MyNetworkCode::Unknown(2) { // <- The library does not construct this value as it used to…
        // …  the special case is not handled anymore; no warning and no error
        // is emitted by the compiler, so it’s very easy to overlook this
    }
}
```

Several other concerns arise:

- `Unknown(2)` and `ThirdValue` are conceptually the same thing, but are represented differently in memory.
- The default `PartialEq` implementation that can be derived will return `false` when testing for
  equality (i.e.: `Unknown(2) != ThirdValue`). Fixing this requires manual implementation of `PartialEq`.
- Even if `PartialEq` is fixed, the pattern matching issue can’t be fixed.
- The size of this type is bigger than necessary.

All in all, this can be considered a potential source of bugs in code consuming the API, and the
bottom line is to avoid type definitions that allow for the same thing to be represented in two
different ways, i.e: different "type-level values", because the library will not return or "emit"
both at the same time; it’s as if one of the two value was implicitly "dead"[^deranged-note].

[^deranged-note]: Note that [`RangedU32::new_static`][RangedU32_new_static] from [`deranged`][deranged]
(ranged integers library) could help here, but in this case the end result is not ergonomic and still
error-prone as it’s natural to reach for [`RangedU32::get`][RangedU32_get] instead when comparing the
value. This approach would work if a lint was emitted when the compiler detects that the condition
operand will always evaluate to `false`. Built-in ranged integers would be great here.

Another approach would be for `Unknown` not to hold the original value at all, ensuring it can never
overlap with another variant. In this case, users would need to wait for the library to be updated
before they can implement special handling for `ThirdValue`:

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyNetworkCode {
    FirstValue = 0,
    SecondValue = 1,
    // Fallback variant; do not rely on this variant
    Unknown,
}
```

However, there is no guarantee that users will not rely on `Unknown` being emitted anyway. This
approach merely discourages them from doing so by making the fallback variant much less powerful.

The downside here is that one can no longer determine the original payload's value, and the "round-
trip" property is lost because this becomes destructive parsing, with no way to determine how the
structure should be (re)encoded.

Overall, it’s not a very good option either.

Instead, consider providing a newtype struct wrapping the appropriate integer type:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MyNetworkCode(u32);

impl MyNetworkCode {
    pub const FIRST_VALUE: Self = Self(0);
    pub const SECOND_VALUE: Self = Self(1);
}
```

This is exactly [how the `http` crate deals with status codes][http-status-code].

This pattern is used in several places:

- `FailureCode` in the `ironrdp_pdu::nego` module.
- `Code` in the `ironrdp_graphics::rle` module.
- `ClipboardFormatId` in the `ironrdp_cliprdr::pdu::format_list` module.

Of course, the main drawback is that exhaustive matching is not possible.

The question to consider is whether it's genuinely necessary to handle all the possible values
explicitly. It may not often be required or desirable. Since neither the client nor the server
should typically break when the protocol is extended, an older client (not handling the new value)
should generally be able to function properly with a newer server, and vice versa. In other words,
not handling the new value must not be an immediate problem. However, it is often desirable to
handle a subset of possible values or to use it for logging or metric purposes. For these purposes,
it’s actually fine to not do exhaustive matching, and ability to work with unknown values is useful
(e.g.: logging unknown values).

Yet, it can be useful to provide a pattern-matching-friendly API in some cases. In such situations,
it is advisable to also offer a higher-level abstraction, such as an enum, that can be obtained from
the "raw" `MyNetworkCode` value. This pattern is applied in the `ironrdp-rdcleanpath` crate to convert
from a lower-level, future-proof, resilient but awkward-to-use type, `RDCleanPathPdu`, to a high-level,
easier-to-use type, `RDCleanPath`.

Don’t forget that in some cases, the protocol specification explicitly states that other values
MUST always be rejected. In such cases, an `enum` is deemed appropriate.

[RangedU32_new_static]: https://docs.rs/deranged/0.3.8/deranged/struct.RangedU32.html#method.new_static
[RangedU32_get]: https://docs.rs/deranged/0.3.8/deranged/struct.RangedU32.html#method.get
[deranged]: https://docs.rs/deranged/0.3.8/
[http-status-code]: https://docs.rs/http/0.2.9/http/status/struct.StatusCode.html

## On bit flags

The **TL;DR** is:

- Use **both** `from_bits_retain` and `const _ = !0` when resilient parsing is required.
    - `const _ = !0` ensures we don’t accidentally have non resilient or destructive parsing. In
      addition to that, generated methods such as `complement` (`!`) will consider additional bits
      and follow the principle of least surprise (`!!flags == flags`).
    - `from_bits_retain` makes it clear at the call site that preserving all the bits is intentional.
- Use `from_bits` WITHOUT `const _ = !0` when strictness is required (almost never in IronRDP), and
  document why with an in-source comment.

Bit flags are used quite pervasively in the RDP protocol.
IronRDP is relying on the [`bitflags` crate][bitflags] to generate well-defined flags structures,
freeing us from worrying about bitwise logic.

Three notable methods generated by the `bitflags` crate are:

- [`from_bits`][from_bits],
- [`from_bits_truncate`][from_bits_truncate], and
- [`from_bits_retain`][from_bits_retain].

Within IronRDP codebase, `from_bits_retain` should generally be used over `from_bits`, and
`from_bits_truncate` is likely wrong. `from_bits_retain` will simply ignore unknown bits, but will
not unset them (unlike `from_bits_truncate`), i.e.: the underlying `u32` is set exactly to the value
received from the network.

Rationale is:

- PDU decoding and encoding logic should uphold the round-tripping property (`m = encode(decode(m))`),
  and for this property to hold, parsing must be non-destructive (i.e.: lossless),
  but `from_bits_truncate` is destructive (unknown bits are discarded).
- Resilient parsing is generally preferred, ignoring unknown values as long as they are not needed and/or as
  long as ignoring them is causing no harm, but `from_bits` is not lenient

Note that it’s okay to use `from_bits` if strictness is actually required somewhere, but such places must be
documented with a comment explaining why refusing unknown flags is better.

`bitflags` v2.4 also introduced a new syntax in the `bitflags!` macro (<https://github.com/bitflags/bitflags/pull/371>):

```rust
bitflags! {
    pub struct Flags: u32 {
        const A = 0b00000001;
        const B = 0b00000010;
        const C = 0b00000100;

        // The source may set any bits
        const _ = !0; // <- This
    }
}
```

There is crate-level documentation for this: <https://docs.rs/bitflags/2.4.0/bitflags/#externally-defined-flags>

This addition makes `from_bits_truncate` behave exactly like `from_bits_retain`, because all values
are considered to be known and defined. In such cases, `from_bits` also never fails therefore works
precisely the same as `from_bits_retain`, except it’s less ergonomic because it returns a `Result`
which must be needlessly handled.

## Feature Flags

- `std` (depends on `alloc`): enables `std` integration in `ironrdp-error` and `ironrdp-core`.
- `alloc`: enables allocation-dependent code paths while keeping `no_std`-compatible.
- `qoi`, `qoiz`: optional [QOI image format](https://qoiformat.org/) bitmap codec support.
- `arbitrary` (depends on `alloc`): enables [`arbitrary::Arbitrary`](https://docs.rs/arbitrary)
  implementations on PDU types for use under structure-aware fuzzing. See
  [`fuzz/README.md`](../../fuzz/README.md) for the fuzz target organization.

This crate is part of the [IronRDP] project.

[IronRDP]: https://github.com/Devolutions/IronRDP
[bitflags]: https://crates.io/crates/bitflags
[from_bits]: https://docs.rs/bitflags/2.4.0/bitflags/example_generated/struct.Flags.html#method.from_bits
[from_bits_truncate]: https://docs.rs/bitflags/2.4.0/bitflags/example_generated/struct.Flags.html#method.from_bits_truncate
[from_bits_retain]: https://docs.rs/bitflags/2.4.0/bitflags/example_generated/struct.Flags.html#method.from_bits_retain
