#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions

"$builddir"/../src/serial-check
