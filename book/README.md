# moatd documentation

This directory holds the moatd user / developer guide, built with
[`mdbook`](https://rust-lang.github.io/mdBook/).

## Build & view

```sh
cargo install mdbook
mdbook serve book
```

Then open <http://localhost:3000>.

## One-off render to HTML

```sh
mdbook build book
```

Output lands in `book/book/` (which is gitignored).
