# rydcon

A low-level CLI for Ryder devices that is capable of sending basic commands and displaying their
output in hexadecimal.

# Dependencies

- Rust 1.61.0 or later (earlier versions may work but not tested)

# Usage

First, clone the repository with `git clone`. Then, to run `rydcon`:

```
cargo build --release
./target/release/rydcon <port>
```

where `<port>` is the serial port of the Ryder device or simulator.

Hexadecimal commands may be entered directly into the `rydcon` prompt, or their ASCII names may be
used instead (type `help` for a full list). Press `^C` to exit.
