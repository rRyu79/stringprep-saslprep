# stringprep-saslprep

Applies RFC 4013 SASLprep to a Unicode string, mapping non-ASCII spaces, normalizing with NFKC, and rejecting prohibited and bidirectionally-unsafe code points, so authentication identifiers compare consistently across implementations.

```python
from stringprep_saslprep import saslprep, SASLprepError

prepared = saslprep("I\u00ADX")      # -> "IX"
prepared = saslprep("\uFF21\uFF22")  # -> "AB"
try:
    saslprep("bad\u0000char")
except SASLprepError as exc:
    print("rejected:", exc)
```

## Why this exists

SASL authentication protocols compare usernames and passwords as opaque strings, but two visually identical Unicode strings can have different code-point sequences. RFC 4013 defines a fixed preparation profile so that every implementation agrees on a canonical form before comparison. This library implements that profile using only the Python standard library, so it works in locked-down or offline environments where installing a dependency is not an option.

The trade-off is that the prohibited-code-point tables are encoded as explicit membership functions rather than derived from the Unicode database at runtime. This keeps the dependency surface at zero and makes behaviour deterministic across Python versions, at the cost of needing to audit the tables if the underlying RFC tables are ever amended.

## The awkward edge

This library takes the strict reading of RFC 3454 Table A.1: any code point from that table that survives NFKC normalization causes `saslprep` to raise `SASLprepError`. If you need to accept strings containing those characters, you must catch the exception and handle the fallback yourself — the library will not silently pass them through.

The bidirectional check rejects mixed left-to-right / right-to-left strings that do not start and end with a right-to-left character. This is the rule that most often surprises callers who mix scripts in usernames.

## Exported names

- `saslprep(source: str) -> str` — prepare a string per RFC 4013.
- `SASLprepError` — raised on validation failure; a subclass of `ValueError`.

## Running the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

