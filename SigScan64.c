#include "SigScan64.h"

// use characters after 'F' for sig capture tokens
#define SIG_CAPTURE_COUNT ('Z' - 'G' + 1)

typedef struct _SIG_CAPTURE_REFERENCE {
    SIZE_T nOffset;
    BYTE bShift;
    BYTE bValueMask;
} SIG_CAPTURE_REFERENCE, *LPSIG_CAPTURE_REFERENCE;

typedef struct _SIG_EQUALITY_CONSTRAINT {
    SIZE_T nSourceOffset;
    SIZE_T nTargetOffset;
    BYTE bSourceShift;
    BYTE bTargetShift;
    BYTE bValueMask;
} SIG_EQUALITY_CONSTRAINT, *LPSIG_EQUALITY_CONSTRAINT;

static BOOL DecodeSignatureNibble(
    BYTE bCharacter,
    LPBYTE lpNibble
) {
    if (bCharacter >= '0' && bCharacter <= '9') {
        *lpNibble = (BYTE) (bCharacter - '0');
        return TRUE;
    }

    if (bCharacter >= 'A' && bCharacter <= 'F') {
        *lpNibble = (BYTE) (bCharacter - 'A' + 10U);
        return TRUE;
    }

    if (bCharacter >= 'a' && bCharacter <= 'f') {
        *lpNibble = (BYTE) (bCharacter - 'a' + 10U);
        return TRUE;
    }

    return FALSE;
}

static BOOL IsSignatureCapture(
    BYTE bCharacter
) {
    return 'G' <= bCharacter && 'Z' >= bCharacter;
}

static BOOL RegisterSignatureCapture(
    BYTE bIdentifier,
    SIZE_T nOffset,
    BYTE bShift,
    BYTE bValueMask,
    LPSIG_CAPTURE_REFERENCE lpCaptures,
    LPSIG_EQUALITY_CONSTRAINT lpConstraints,
    SIZE_T *lpConstraintCount
) {
    LPSIG_CAPTURE_REFERENCE lpCapture = &lpCaptures[bIdentifier - 'G'];

    if (0 == lpCapture->bValueMask) {
        lpCapture->nOffset = nOffset;
        lpCapture->bShift = bShift;
        lpCapture->bValueMask = bValueMask;
        return TRUE;
    }

    // one identifier cant represent both byte and nibble
    if (bValueMask != lpCapture->bValueMask) {
        return FALSE;
    }

    if (NULL != lpConstraints) {
        LPSIG_EQUALITY_CONSTRAINT lpConstraint = &lpConstraints[(*lpConstraintCount)++];
        lpConstraint->nSourceOffset = lpCapture->nOffset;
        lpConstraint->nTargetOffset = nOffset;
        lpConstraint->bSourceShift = lpCapture->bShift;
        lpConstraint->bTargetShift = bShift;
        lpConstraint->bValueMask = bValueMask;
    }
    return TRUE;
}

static BOOL DecodeSignatureToken(
    UMASK wToken,
    SIZE_T nOffset,
    PUMASK lpCompiled,
    LPSIG_CAPTURE_REFERENCE lpCaptures,
    LPSIG_EQUALITY_CONSTRAINT lpConstraints,
    SIZE_T *lpConstraintCount
) {
    if (wToken <= 0xFFU || UMASK_WC == wToken) {
        *lpCompiled = wToken;
        return TRUE;
    }

    CONST BYTE bHigh = (BYTE) (wToken >> 8);
    CONST BYTE bLow = (BYTE) wToken;
    BYTE bNibble = 0;
    UMASK wCompiled = 0;

    // 'XX' captures an entire byte, not two identical nibbles
    if (bHigh == bLow && IsSignatureCapture(bHigh)) {
        if (!RegisterSignatureCapture(
            bHigh, nOffset, 0, 0xFFU,
            lpCaptures, lpConstraints, lpConstraintCount
        )) {
            return FALSE;
        }

        *lpCompiled = 0xFF00U;
        return TRUE;
    }

    if ('?' == bHigh || IsSignatureCapture(bHigh)) {
        wCompiled |= 0xF000U;

        if (IsSignatureCapture(bHigh) && !RegisterSignatureCapture(
            bHigh, nOffset, 4, 0x0FU,
            lpCaptures, lpConstraints, lpConstraintCount
        )) {
            return FALSE;
        }
    } else {
        if (!DecodeSignatureNibble(bHigh, &bNibble)) {
            return FALSE;
        }

        wCompiled |= (UMASK) (bNibble << 4);
    }

    if ('?' == bLow || IsSignatureCapture(bLow)) {
        wCompiled |= 0x0F00U;

        if (IsSignatureCapture(bLow) && !RegisterSignatureCapture(
            bLow, nOffset, 0, 0x0FU,
            lpCaptures, lpConstraints, lpConstraintCount
        )) {
            return FALSE;
        }
    } else {
        if (!DecodeSignatureNibble(bLow, &bNibble)) {
            return FALSE;
        }

        wCompiled |= bNibble;
    }

    *lpCompiled = wCompiled;
    return TRUE;
}

static BOOL MatchCompiledSignatureByte(
    BYTE bValue,
    UMASK wToken
) {
    CONST BYTE bCare = (BYTE) ~(wToken >> 8);

    return 0 == ((bValue ^ (BYTE) wToken) & bCare);
}

static BOOL MatchSignatureConstraints(
    LPCBYTE lpCandidate,
    CONST SIG_EQUALITY_CONSTRAINT *lpConstraints,
    SIZE_T nConstraints
) {
    for (SIZE_T j = 0; j < nConstraints; j++) {
        CONST SIG_EQUALITY_CONSTRAINT *lpConstraint = &lpConstraints[j];
        CONST BYTE bSource = (BYTE) (
            (lpCandidate[lpConstraint->nSourceOffset] >> lpConstraint->bSourceShift) &
            lpConstraint->bValueMask
        );
        CONST BYTE bTarget = (BYTE) (
            (lpCandidate[lpConstraint->nTargetOffset] >> lpConstraint->bTargetShift) &
            lpConstraint->bValueMask
        );

        if (bSource != bTarget) {
            return FALSE;
        }
    }

    return TRUE;
}

static SIZE_T SearchMaskedSignatureInternal(
    LPCVOID lpSearchBase,
    SIZE_T cbSearch,
    PCUMASK lpSignature,
    SIZE_T nSignature,
    LPCBYTE* lpMatches,
    SIZE_T nMaxMatches
) {
    if (NULL == lpSearchBase || NULL == lpSignature || NULL == lpMatches) {
        return 0;
    }

    if (0 == nSignature || 0 == nMaxMatches || nSignature > cbSearch) {
        return 0;
    }

    UMASK awCompiled[UMASK_STACK_COUNT] = { 0 };
    SIG_EQUALITY_CONSTRAINT aStackConstraints[UMASK_STACK_COUNT * 2U] = { 0 };
    SIG_CAPTURE_REFERENCE aCaptures[SIG_CAPTURE_COUNT] = { 0 };
    PUMASK lpCompiled = awCompiled;
    LPSIG_EQUALITY_CONSTRAINT lpConstraints = aStackConstraints;
    
    SIZE_T nConstraints = 0;
    SIZE_T nMatches = 0;
    SIZE_T nAnchor = nSignature;
    BYTE bAnchorCare = 0;

    LPCBYTE lpBytes = (LPCBYTE) lpSearchBase;
    CONST SIZE_T cStartCount = cbSearch - nSignature + 1;
    SIZE_T i = 0;

    if (nSignature > ARRAYSIZE(awCompiled)) {
        if (nSignature > (SIZE_T) -1 / sizeof(*lpCompiled) ||
            nSignature > (SIZE_T) -1 / (2U * sizeof(*lpConstraints))) {
            return 0;
        }

        lpCompiled = (PUMASK) malloc(nSignature * sizeof(*lpCompiled));

        if (NULL == lpCompiled) {
            return 0;
        }

        lpConstraints = (LPSIG_EQUALITY_CONSTRAINT) malloc(
            nSignature * 2U * sizeof(*lpConstraints)
        );

        if (NULL == lpConstraints) {
            goto _FINAL;
        }
    }

    // Compile fixed bits and named equality constraints before scanning.
    for (SIZE_T j = 0; j < nSignature; j++) {
        if (!DecodeSignatureToken(
            lpSignature[j], j, &lpCompiled[j],
            aCaptures, lpConstraints, &nConstraints
        )) {
            goto _FINAL;
        }

        CONST BYTE bCare = (BYTE) ~(lpCompiled[j] >> 8);

        if (0 == bCare) {
            continue;
        }

        if (nSignature == nAnchor || (0xFFU == bCare && bAnchorCare != 0xFFU)) {
            nAnchor = j;
            bAnchorCare = bCare;
        }
    }

    while (i < cStartCount && nMatches < nMaxMatches) {
        SIZE_T j = nSignature;

        if (nAnchor != nSignature) {
            if (0xFFU == bAnchorCare) {
                LPCBYTE lpHit = (LPCBYTE) memchr(
                    lpBytes + i + nAnchor,
                    (BYTE) lpCompiled[nAnchor],
                    cStartCount - i
                );

                if (NULL == lpHit) {
                    break;
                }

                i = (SIZE_T) (lpHit - (lpBytes + nAnchor));
            } else if (!MatchCompiledSignatureByte(lpBytes[i + nAnchor], lpCompiled[nAnchor])) {
                i++;
                continue;
            }

            for (j = 0; j < nSignature; j++) {
                if (!MatchCompiledSignatureByte(lpBytes[i + j], lpCompiled[j])) {
                    break;
                }
            }
        }

        if (nSignature == j && MatchSignatureConstraints(
            lpBytes + i, lpConstraints, nConstraints
        )) {
            lpMatches[nMatches++] = lpBytes + i;
            i += nSignature;
        } else {
            i++;
        }
    }

_FINAL:
    if (lpCompiled != awCompiled) {
        free(lpCompiled);
    }

    if (lpConstraints != aStackConstraints) {
        free(lpConstraints);
    }

    return nMatches;
}

BOOL ValidateMaskedSignature(
    _In_reads_(SignatureCount) PCUMASK Signature,
    _In_ SIZE_T SignatureCount
) {
    SIG_CAPTURE_REFERENCE aCaptures[SIG_CAPTURE_COUNT] = { 0 };

    if (NULL == Signature || 0 == SignatureCount) {
        return FALSE;
    }

    for (SIZE_T i = 0; i < SignatureCount; i++) {
        UMASK wCompiled = 0;

        if (!DecodeSignatureToken(
            Signature[i], i, &wCompiled, aCaptures, NULL, NULL
        )) {
            return FALSE;
        }
    }

    return TRUE;
}

LPCBYTE SearchForMaskedSignature(
    _In_reads_bytes_(SearchSize) LPCVOID SearchBase,
    _In_ SIZE_T SearchSize,
    _In_reads_(SignatureCount) PCUMASK Signature,
    _In_ SIZE_T SignatureCount
) {
    LPCBYTE lpMatch = NULL;

    SearchMaskedSignatureInternal(
        SearchBase,
        SearchSize,
        Signature,
        SignatureCount,
        &lpMatch,
        1
    );

    return lpMatch;
}

SIZE_T SearchForMaskedSignatureAll(
    _In_reads_bytes_(SearchSize) LPCVOID SearchBase,
    _In_ SIZE_T SearchSize,
    _In_reads_(SignatureCount) PCUMASK Signature,
    _In_ SIZE_T SignatureCount,
    _Out_writes_to_(MaxMatches, return) LPCBYTE* Matches,
    _In_ SIZE_T MaxMatches
) {
    return SearchMaskedSignatureInternal(
        SearchBase,
        SearchSize,
        Signature,
        SignatureCount,
        Matches,
        MaxMatches
    );
}
