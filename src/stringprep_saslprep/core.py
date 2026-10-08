"""Implementation of RFC 4013 SASLprep.

SASLprep is a profile of RFC 3454 stringprep used to prepare Unicode
strings prior to transmission in SASL authentication protocols. It
applies a sequence of normalization and mapping steps to produce a
canonical form suitable for comparison, and rejects code points that
are inappropriate for authentication strings.

The mapping and normalization operations are implemented using only
the Python standard library (unicodedata for NFKC, and explicit tables
for the prohibited code points), which keeps the library usable in
environments with no network access and no compiled dependencies.
"""

from __future__ import annotations

import unicodedata

__all__ = ["saslprep", "SASLprepError"]


class SASLprepError(ValueError):
    """Raised when an input string violates RFC 4013 SASLprep rules.

    A distinct subclass of ValueError is used so that callers can
    distinguish validation failures from ordinary runtime errors
    without catching a broad exception type.
    """


def _stringprep_in_table_c11(c: str) -> bool:
    """RFC 3454 Table C.1.1: non-ASCII space characters.

    These are space-like code points outside ASCII that would otherwise
    be indistinguishable from U+0020 after normalization and must be
    rejected to prevent visual confusion in identifiers.
    """
    code = ord(c)
    return code in (
        0x00A0,  # NO-BREAK SPACE
        0x1680,  # OGHAM SPACE MARK
        0x2000,  # EN QUAD
        0x2001,  # EM QUAD
        0x2002,  # EN SPACE
        0x2003,  # EM SPACE
        0x2004,  # THREE-PER-EM SPACE
        0x2005,  # FOUR-PER-EM SPACE
        0x2006,  # SIX-PER-EM SPACE
        0x2007,  # FIGURE SPACE
        0x2008,  # PUNCTUATION SPACE
        0x2009,  # THIN SPACE
        0x200A,  # HAIR SPACE
        0x200B,  # ZERO WIDTH SPACE
        0x202F,  # NARROW NO-BREAK SPACE
        0x205F,  # MEDIUM MATHEMATICAL SPACE
        0x3000,  # IDEOGRAPHIC SPACE
    )


def _stringprep_in_table_c12(c: str) -> bool:
    """RFC 3454 Table C.1.2: ASCII control characters.

    Control characters in the C0 range are not meaningful content in
    authentication strings and are prohibited to avoid ambiguity and
    transport-layer issues.
    """
    code = ord(c)
    return 0x0000 <= code <= 0x001F or code == 0x007F


def _stringprep_in_table_c21(c: str) -> bool:
    """RFC 3454 Table C.2.1: non-ASCII control characters.

    Extends the control-character prohibition to non-ASCII ranges,
    including the DEL analogue U+007F's counterparts and C1 controls.
    """
    code = ord(c)
    return (
        0x0080 <= code <= 0x009F
        or code == 0x06DD
        or code == 0x070F
        or code == 0x180E
        or code == 0x200C
        or code == 0x200D
        or code == 0x2028
        or code == 0x2029
        or (0x2060 <= code <= 0x2063)
        or (0x206A <= code <= 0x206F)
        or code == 0xFEFF
        or (0xFFF9 <= code <= 0xFFFC)
        or code == 0x1D173
        or code == 0x1D174
        or code == 0x1D175
        or (0xE0001 <= code <= 0xE007F)
        or (0xE0100 <= code <= 0xE01EF)
    )


def _stringprep_in_table_c22(c: str) -> bool:
    """RFC 3454 Table C.2.2: private use characters.

    Private-use code points have no standardized meaning and therefore
    cannot form part of a comparable identifier across implementations.
    """
    code = ord(c)
    return (
        (0xE000 <= code <= 0xF8FF)
        or (0xF0000 <= code <= 0xFFFFD)
        or (0x100000 <= code <= 0x10FFFD)
    )


def _stringprep_in_table_c3(c: str) -> bool:
    """RFC 3454 Table C.3: private-use characters in planes.

    Supplementary private-use areas are rejected for the same reason as
    Table C.2.2.
    """
    code = ord(c)
    return (
        (0xF0000 <= code <= 0xFFFFD)
        or (0x100000 <= code <= 0x10FFFD)
    )


def _stringprep_in_table_c4(c: str) -> bool:
    """RFC 3454 Table C.4: non-character code points.

    Code points reserved permanently as non-characters are unsuitable
    for interchange in authentication strings.
    """
    code = ord(c)
    if code in (0xFFFE, 0xFFFF, 0x1FFFE, 0x1FFFF, 0x2FFFE, 0x2FFFF,
               0x3FFFE, 0x3FFFF, 0x4FFFE, 0x4FFFF, 0x5FFFE, 0x5FFFF,
               0x6FFFE, 0x6FFFF, 0x7FFFE, 0x7FFFF, 0x8FFFE, 0x8FFFF,
               0x9FFFE, 0x9FFFF, 0xAFFFE, 0xAFFFF, 0xBFFFE, 0xBFFFF,
               0xCFFFE, 0xCFFFF, 0xDFFFE, 0xDFFFF, 0xEFFFE, 0xEFFFF,
               0xFFFFE, 0xFFFFF):
        return True
    if 0xFDD0 <= code <= 0xFDEF:
        return True
    return False


def _stringprep_in_table_c5(c: str) -> bool:
    """RFC 3454 Table C.5: surrogate code points.

    Surrogates cannot appear in valid Unicode text and must be rejected
    before any further processing.
    """
    code = ord(c)
    return 0xD800 <= code <= 0xDFFF


def _stringprep_in_table_c6(c: str) -> bool:
    """RFC 3454 Table C.6: non-character code points, continued.

    Additional reserved non-character code points not covered by
    Table C.4.
    """
    code = ord(c)
    return code in (
        0xFFFE, 0xFFFF, 0x1FFFE, 0x1FFFF, 0x2FFFE, 0x2FFFF,
        0x3FFFE, 0x3FFFF, 0x4FFFE, 0x4FFFF, 0x5FFFE, 0x5FFFF,
        0x6FFFE, 0x6FFFF, 0x7FFFE, 0x7FFFF, 0x8FFFE, 0x8FFFF,
        0x9FFFE, 0x9FFFF, 0xAFFFE, 0xAFFFF, 0xBFFFE, 0xBFFFF,
        0xCFFFE, 0xCFFFF, 0xDFFFE, 0xDFFFF, 0xEFFFE, 0xEFFFF,
        0xFFFFE, 0xFFFFF,
    )


def _stringprep_in_table_c7(c: str) -> bool:
    """RFC 3454 Table C.7: inappropriate for plain text.

    Code points that are formatting controls inappropriate for plain
    text representation are rejected to keep identifiers visually
    unambiguous.
    """
    code = ord(c)
    return code in (0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0xFFFD)


def _stringprep_in_table_c8(c: str) -> bool:
    """RFC 3454 Table C.8: inappropriate for canonical representation.

    These code points have visually confusable canonical forms and are
    excluded to preserve the integrity of identifier comparison.
    """
    code = ord(c)
    return (
        0x0340 <= code <= 0x0341
        or code in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
                   0x202E, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E,
                   0x206F)
    )


def _stringprep_in_table_c9(c: str) -> bool:
    """RFC 3454 Table C.9: change display and property code points.

    Deprecated or display-modifying code points inappropriate for
    stable identifiers.
    """
    code = ord(c)
    return code in (
        0x0149, 0x0670, 0x0F95, 0x2329, 0x232A, 0x2E80, 0x2E84,
        0x2E86, 0x2E87, 0x2E88, 0x2E8A, 0x2E8B, 0x2E8C, 0x2E8D,
        0x2E90, 0x2E91, 0x2E92, 0x2E93, 0x2E94, 0x2E95, 0x2E96,
        0x2E97, 0x2E98, 0x2E99, 0x2E9A, 0x2E9B, 0x2E9C, 0x2E9D,
        0x2E9E, 0x2E9F, 0x2EA0, 0x2EA1, 0x2EA2, 0x2EA3, 0x2EA4,
        0x2EA5, 0x2EA6, 0x2EA7, 0x2EA8, 0x2EA9, 0x2EAA, 0x2EAB,
        0x2EAC, 0x2EAD, 0x2EAE, 0x2EAF, 0x2EB0, 0x2EB1, 0x2EB2,
        0x2EB3, 0x2EB4, 0x2EB5, 0x2EB6, 0x2EB7, 0x2EB8, 0x2EB9,
        0x2EBA, 0x2EBB, 0x2EBC, 0x2EBD, 0x2EBE, 0x2EBF, 0x2EC0,
        0x2EC1, 0x2EC2, 0x2EC3, 0x2EC4, 0x2EC5, 0x2EC6, 0x2EC7,
        0x2EC8, 0x2EC9, 0x2ECA, 0x2ECB, 0x2ECC, 0x2ECD, 0x2ECE,
        0x2ECF, 0x2ED0, 0x2ED1, 0x2ED2, 0x2ED3, 0x2ED4, 0x2ED5,
        0x2ED6, 0x2ED7, 0x2ED8, 0x2ED9, 0x2EDA, 0x2EDB, 0x2EDC,
        0x2EDD, 0x2EDE, 0x2EDF, 0x2EE0, 0x2EE1, 0x2EE2, 0x2EE3,
        0x2EE4, 0x2EE5, 0x2EE6, 0x2EE7, 0x2EE8, 0x2EE9, 0x2EEA,
        0x2EEB, 0x2EEC, 0x2EED, 0x2EEE, 0x2EEF,
    )


def _stringprep_in_table_a1(c: str) -> bool:
    """RFC 3454 Table A.1: characters with deprecated or unusual mappings.

    These are code points whose NFKC normalization is generally
    considered inappropriate for SASL identifiers. RFC 4013 section
    2.3 requires that, if a string contains any code point listed in
    Table A.1 after mapping and normalization, and the character is
    not itself normalized away, the string must be rejected unless
    the caller opts into allowing such strings.

    This implementation takes the strict interpretation: any presence
    of a Table A.1 code point after NFKC normalization is an error.
    This is the conservative choice recommended for protocol
    implementations that cannot predict the comparison behaviour of
    all peers.
    """
    code = ord(c)
    return (
        code == 0x0220
        or code == 0x0221
        or code == 0x0222
        or code == 0x0223
        or code == 0x0224
        or code == 0x0225
        or code == 0x0226
        or code == 0x0227
        or code == 0x0228
        or code == 0x0229
        or code == 0x022A
        or code == 0x022B
        or code == 0x022C
        or code == 0x022D
        or code == 0x022E
        or code == 0x022F
        or code == 0x0230
        or code == 0x0231
        or code == 0x0232
        or code == 0x0233
        or code == 0x0234
        or code == 0x0235
        or code == 0x0236
        or code == 0x0237
        or code == 0x0238
        or code == 0x0239
        or code == 0x023A
        or code == 0x023B
        or code == 0x023C
        or code == 0x023D
        or code == 0x023E
        or code == 0x023F
        or code == 0x0240
        or code == 0x0241
        or code == 0x0242
        or code == 0x0243
        or code == 0x0244
        or code == 0x0245
        or code == 0x0246
        or code == 0x0247
        or code == 0x0248
        or code == 0x0249
        or code == 0x024A
        or code == 0x024B
        or code == 0x024C
        or code == 0x024D
        or code == 0x024E
        or code == 0x024F
        or code == 0x0250
        or code == 0x0251
        or code == 0x0252
        or code == 0x0253
        or code == 0x0254
        or code == 0x0255
        or code == 0x0256
        or code == 0x0257
        or code == 0x0258
        or code == 0x0259
        or code == 0x025A
        or code == 0x025B
        or code == 0x025C
        or code == 0x025D
        or code == 0x025E
        or code == 0x025F
        or code == 0x0260
        or code == 0x0261
        or code == 0x0262
        or code == 0x0263
        or code == 0x0264
        or code == 0x0265
        or code == 0x0266
        or code == 0x0267
        or code == 0x0268
        or code == 0x0269
        or code == 0x026A
        or code == 0x026B
        or code == 0x026C
        or code == 0x026D
        or code == 0x026E
        or code == 0x026F
        or code == 0x0270
        or code == 0x0271
        or code == 0x0272
        or code == 0x0273
        or code == 0x0274
        or code == 0x0275
        or code == 0x0276
        or code == 0x0277
        or code == 0x0278
        or code == 0x0279
        or code == 0x027A
        or code == 0x027B
        or code == 0x027C
        or code == 0x027D
        or code == 0x027E
        or code == 0x027F
        or code == 0x0280
        or code == 0x0281
        or code == 0x0282
        or code == 0x0283
        or code == 0x0284
        or code == 0x0285
        or code == 0x0286
        or code == 0x0287
        or code == 0x0288
        or code == 0x0289
        or code == 0x028A
        or code == 0x028B
        or code == 0x028C
        or code == 0x028D
        or code == 0x028E
        or code == 0x028F
        or code == 0x0290
        or code == 0x0291
        or code == 0x0292
    )


def _apply_mapping(s: str) -> str:
    """RFC 4013 section 2.1 mapping step.

    Maps non-ASCII space characters (U+00A0) and the zero-width joiner
    / non-joiner (U+200C, U+200D) to ASCII space and to nothing,
    respectively. The space mapping keeps visible separation intact;
    the ZW* removal prevents them from surviving normalization in a way
    that would alter comparison of visually identical strings.
    """
    out = []
    for c in s:
        code = ord(c)
        if code == 0x00A0:
            out.append(" ")
        elif code in (0x200C, 0x200D):
            continue
        else:
            out.append(c)
    return "".join(out)


def _normalize(s: str) -> str:
    """RFC 4013 section 2.2 normalization step: NFKC.

    NFKC is chosen over NFC because SASL identifiers frequently contain
    compatibility characters (e.g. fullwidth Latin letters) that must
    fold to a canonical form for cross-implementation comparison.
    """
    return unicodedata.normalize("NFKC", s)


def _check_prohibited(s: str) -> None:
    """RFC 4013 section 2.3 prohibited output check.

    Walks the post-normalization string and raises SASLprepError if any
    code point appears in the SASLprep prohibited tables (the union of
    RFC 3454 tables C.1.1, C.1.2, C.2.1, C.2.2, C.3, C.4, C.5, C.6,
    C.7, C.8, and C.9).
    """
    for c in s:
        if (
            _stringprep_in_table_c11(c)
            or _stringprep_in_table_c12(c)
            or _stringprep_in_table_c21(c)
            or _stringprep_in_table_c22(c)
            or _stringprep_in_table_c3(c)
            or _stringprep_in_table_c4(c)
            or _stringprep_in_table_c5(c)
            or _stringprep_in_table_c6(c)
            or _stringprep_in_table_c7(c)
            or _stringprep_in_table_c8(c)
            or _stringprep_in_table_c9(c)
        ):
            raise SASLprepError(
                "prohibited code point U+{:04X} in SASLprep output".format(ord(c))
            )


def _check_bidi(s: str) -> None:
    """RFC 4013 section 2.4 / RFC 3454 section 6 bidirectional check.

    The bidirectional rules prevent strings whose visual rendering
    could differ from their logical order under right-to-left display.
    A string containing both RandALCat and LCat characters must have
    the RandALCat characters at both the start and the end, and must
    not contain RandALCat characters only in the middle.
    """
    if not s:
        return
    has_randal = any(_is_randalcat(c) for c in s)
    has_lcat = any(_is_lcat(c) for c in s)
    if has_randal and has_lcat:
        if not _is_randalcat(s[0]) or not _is_randalcat(s[-1]):
            raise SASLprepError(
                "bidirectional check failed: string contains both "
                "RandALCat and LCat characters but does not start and "
                "end with a RandALCat character"
            )


def _is_randalcat(c: str) -> bool:
    """RFC 3454 section 6, category RandALCat.

    Code points with bidirectional property R, AL, or AN. These are the
    right-to-left and Arabic-number characters that trigger the
    bidirectional rules when mixed with left-to-right characters.
    """
    code = ord(c)
    return (
        (0x05BE <= code <= 0x05BE)
        or (0x05C0 <= code <= 0x05C0)
        or (0x05C3 <= code <= 0x05C3)
        or (0x05D0 <= code <= 0x05EA)
        or (0x05F0 <= code <= 0x05F4)
        or code == 0x061B
        or code == 0x061F
        or (0x0621 <= code <= 0x063A)
        or (0x0640 <= code <= 0x064A)
        or (0x066D <= code <= 0x066F)
        or (0x0671 <= code <= 0x06D5)
        or code == 0x06DD
        or (0x06E5 <= code <= 0x06E6)
        or (0x06FA <= code <= 0x06FE)
        or (0x0700 <= code <= 0x070D)
        or code == 0x0710
        or (0x0712 <= code <= 0x072C)
        or code == 0x0780
        or (0x0781 <= code <= 0x07A5)
        or code == 0x07B1
        or code == 0x200E
        or code == 0x200F
        or code == 0xFB1D
        or (0xFB1F <= code <= 0xFB28)
        or (0xFB2A <= code <= 0xFB36)
        or (0xFB38 <= code <= 0xFB3C)
        or code == 0xFB3E
        or (0xFB40 <= code <= 0xFB41)
        or (0xFB43 <= code <= 0xFB44)
        or (0xFB46 <= code <= 0xFBB1)
        or (0xFBD3 <= code <= 0xFD3D)
        or (0xFD50 <= code <= 0xFD8F)
        or (0xFD92 <= code <= 0xFDC7)
        or (0xFDF0 <= code <= 0xFDFC)
        or (0xFE70 <= code <= 0xFE74)
        or (0xFE76 <= code <= 0xFEFC)
    )


def _is_lcat(c: str) -> bool:
    """RFC 3454 section 6, category LCat.

    Characters with bidirectional property L, EN, ES, ET, AN, CS, or
    ON that are not RandALCat. Used to detect mixed-direction strings.
    """
    code = ord(c)
    return (
        (0x0041 <= code <= 0x005A)
        or (0x0061 <= code <= 0x007A)
        or (0x00AA <= code <= 0x00AA)
        or (0x00B5 <= code <= 0x00B5)
        or (0x00BA <= code <= 0x00BA)
        or (0x00C0 <= code <= 0x00D6)
        or (0x00D8 <= code <= 0x00F6)
        or (0x00F8 <= code <= 0x0220)
        or (0x0222 <= code <= 0x0233)
        or (0x0250 <= code <= 0x02AD)
        or (0x02B0 <= code <= 0x02B8)
        or (0x02BB <= code <= 0x02C1)
        or code == 0x02D0
        or code == 0x02D1
        or (0x02E0 <= code <= 0x02E4)
        or code == 0x037A
        or code == 0x0386
        or (0x0388 <= code <= 0x038A)
        or code == 0x038C
        or (0x038E <= code <= 0x03A1)
        or (0x03A3 <= code <= 0x03CE)
        or (0x03D0 <= code <= 0x03D6)
        or code == 0x03DA
        or code == 0x03DC
        or code == 0x03DE
        or code == 0x03E0
        or (0x03E2 <= code <= 0x03F3)
        or (0x0401 <= code <= 0x040C)
        or (0x040E <= code <= 0x044F)
        or (0x0451 <= code <= 0x045C)
        or (0x045E <= code <= 0x0481)
        or (0x0490 <= code <= 0x04C4)
        or (0x04C7 <= code <= 0x04C8)
        or (0x04CB <= code <= 0x04CC)
        or (0x04D0 <= code <= 0x04F9)
        or (0x0531 <= code <= 0x0556)
        or code == 0x0559
        or (0x0561 <= code <= 0x0587)
        or code == 0x05B0
        or code == 0x05B1
        or code == 0x05B2
        or code == 0x05B3
        or code == 0x05B4
        or code == 0x05B5
        or code == 0x05B6
        or code == 0x05B7
        or code == 0x05B8
        or code == 0x05B9
        or code == 0x05BA
        or code == 0x05BB
        or code == 0x05BC
        or code == 0x05BD
        or code == 0x05BF
        or code == 0x05C1
        or code == 0x05C2
        or code == 0x05C4
        or code == 0x05D0
        or code == 0x05D1
        or code == 0x05D2
        or code == 0x05D3
        or code == 0x05D4
        or code == 0x05D5
        or code == 0x05D6
        or code == 0x05D7
        or code == 0x05D8
        or code == 0x05D9
        or code == 0x05DA
        or code == 0x05DB
        or code == 0x05DC
        or code == 0x05DD
        or code == 0x05DE
        or code == 0x05DF
        or code == 0x05E0
        or code == 0x05E1
        or code == 0x05E2
        or code == 0x05E3
        or code == 0x05E4
        or code == 0x05E5
        or code == 0x05E6
        or code == 0x05E7
        or code == 0x05E8
        or code == 0x05E9
        or code == 0x05EA
        or code == 0x0660
        or code == 0x0661
        or code == 0x0662
        or code == 0x0663
        or code == 0x0664
        or code == 0x0665
        or code == 0x0666
        or code == 0x0667
        or code == 0x0668
        or code == 0x0669
        or code == 0x06F0
        or code == 0x06F1
        or code == 0x06F2
        or code == 0x06F3
        or code == 0x06F4
        or code == 0x06F5
        or code == 0x06F6
        or code == 0x06F7
        or code == 0x06F8
        or code == 0x06F9
    )


def saslprep(source: str) -> str:
    """Apply RFC 4013 SASLprep to a Unicode string.

    Performs the mapping, NFKC normalization, prohibited-output check,
    and bidirectional check specified by RFC 4013, returning the
    prepared string suitable for use in SASL authentication.

    The strict interpretation of RFC 3454 Table A.1 is used: any code
    point from Table A.1 that survives NFKC normalization causes the
    call to raise SASLprepError. Callers that need to handle such
    inputs should catch SASLprepError and decide on a fallback.

    Args:
        source: The input Unicode string to prepare.

    Returns:
        The SASLprep-prepared string.

    Raises:
        SASLprepError: If the input contains prohibited code points,
            fails the bidirectional check, or contains a Table A.1
            character after normalization.
        TypeError: If the input is not a str.
    """
    if not isinstance(source, str):
        raise TypeError("saslprep() requires a str argument")

    mapped = _apply_mapping(source)
    normalized = _normalize(mapped)
    _check_prohibited(normalized)
    _check_bidi(normalized)
    for c in normalized:
        if _stringprep_in_table_a1(c):
            raise SASLprepError(
                "unmapped Table A.1 code point U+{:04X} in SASLprep "
                "output".format(ord(c))
            )
    return normalized
