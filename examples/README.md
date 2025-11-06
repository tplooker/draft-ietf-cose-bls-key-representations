Scripts for generating examples
===

This directory hosts tools for generating examples to include in the draft.


Usage
---

Use the script `inject-generated-content.sh` to generate and inject the content into the draft:

```sh
$ cd examples
$ ./inject-generated-content.sh
```

If run with `--check`, the script will return a nonzero exit code if it results in any changes:

```sh
$ ./inject-generated-content.sh --check
```

Alternatively, you can run the content generation tool manually. For example:

```sh
$ cargo run --release -- BLS12381G1:0:jwk
$ cargo run --release -- BLS12381G1:1:jwk

$ cargo run --release -- BLS12381G1:0:cwk BLS12381G1:1:cwk
$ cargo run --release -- BLS12381G1:0:cddl BLS12381G1:1:cddl

$ cargo run --release -- BLS12381G1:0:jwk BLS12381G1:0:cwk BLS12381G1:0:cddl
$ cargo run --release -- BLS12381G1:1:jwk BLS12381G1:1:cwk BLS12381G1:1:cddl
```

Then paste the tool outputs into the respective relevant part of the draft.
