// AI-gen
#include "../SigScan64.h"

#include <assert.h>
#include <stdio.h>

static VOID TestNamedByteAndHighNibble(VOID) {
    CONST BYTE abData[] = {
        0x4C, 0x89, 0x65, 0xF7, 0x4C, 0x89, 0x66, 0xFF, // Wrong X
        0x4C, 0x89, 0x65, 0xF7, 0x4C, 0x89, 0x65, 0xEF, // Wrong Y
        0x4C, 0x89, 0x65, 0xF7, 0x4C, 0x89, 0x65, 0xFF  // Match
    };
    CONST UMASK aPattern[] = {
        0x4C, 0x89, 'XX', 'Y?', 0x4C, 0x89, 'XX', 'Y?'
    };

    assert(abData + 16 == SearchForMaskedSignature(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern)
    ));
}

static VOID TestNibblePositions(VOID) {
    CONST BYTE abData[] = { 0xA7, 0x7D, 0xB8, 0x8F };
    CONST UMASK aPattern[] = { '?X', 'X?', '?Y', 'Y?' };
    CONST UMASK aSwapped[] = { 'XY', 'YX' };
    CONST BYTE abSwapped[] = { 0xA3, 0x3A };

    assert(abData == SearchForMaskedSignature(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern)
    ));
    assert(abSwapped == SearchForMaskedSignature(
        abSwapped, sizeof(abSwapped), aSwapped, ARRAYSIZE(aSwapped)
    ));
}

static VOID TestUnanchoredCaptures(VOID) {
    CONST BYTE abData[] = { 0x12, 0x34, 0x55, 0x55 };
    CONST UMASK aPattern[] = { 'XX', 'XX' };
    CONST BYTE abNibbles[] = { 0xA1, 0xA9 };
    CONST UMASK aNibblePattern[] = { 'Y?', 'Y?' };

    assert(abData + 2 == SearchForMaskedSignature(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern)
    ));
    assert(abNibbles == SearchForMaskedSignature(
        abNibbles, sizeof(abNibbles), aNibblePattern,
        ARRAYSIZE(aNibblePattern)
    ));
}

static VOID TestExistingMasks(VOID) {
    CONST BYTE abData[] = { 0x48, 0x8B, 0x71, 0x2F, 0xA5 };
    CONST UMASK aPattern[] = { 0x48, 0x8B, '7?', '?F', UMASK_WC };
    // 0x3F3F is the encoded '??' token without C's trigraph ambiguity.
    CONST UMASK aWildcard[] = { 0x3F3FU, 0x3F3FU };

    assert(abData == SearchForMaskedSignature(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern)
    ));
    assert(abData == SearchForMaskedSignature(
        abData, sizeof(abData), aWildcard, ARRAYSIZE(aWildcard)
    ));
}

static VOID TestInvalidCaptures(VOID) {
    CONST BYTE abData[] = { 0xA1, 0xA1 };
    CONST UMASK aMixedWidth[] = { 'XX', 'X?' };
    CONST UMASK aInvalid[] = { 'Q!', 0xA1 };

    assert(NULL == SearchForMaskedSignature(
        abData, sizeof(abData), aMixedWidth, ARRAYSIZE(aMixedWidth)
    ));
    assert(NULL == SearchForMaskedSignature(
        abData, sizeof(abData), aInvalid, ARRAYSIZE(aInvalid)
    ));
}

static VOID TestSignatureValidation(VOID) {
    CONST UMASK aNamed[] = { 0x4C, 0x89, 'XX', 'Y?', 'XX', 'Y?' };
    CONST UMASK aMixedWidth[] = { 'XX', '?X' };
    CONST UMASK aInvalidToken[] = { 'Q!' };
    CONST UMASK aLegacy[] = { 0x48, 0x8B, 0x3F3FU, '?F', UMASK_WC };

    assert(ValidateMaskedSignature(aNamed, ARRAYSIZE(aNamed)));
    assert(ValidateMaskedSignature(aLegacy, ARRAYSIZE(aLegacy)));
    assert(!ValidateMaskedSignature(aMixedWidth, ARRAYSIZE(aMixedWidth)));
    assert(!ValidateMaskedSignature(aInvalidToken, ARRAYSIZE(aInvalidToken)));
    assert(!ValidateMaskedSignature(NULL, 0));
    assert(!ValidateMaskedSignature(aNamed, 0));
}

static VOID TestLargeSignature(VOID) {
    BYTE abData[UMASK_STACK_COUNT + 3U] = { 0 };
    UMASK aPattern[UMASK_STACK_COUNT + 3U] = { 0 };

    for (SIZE_T i = 0; i < ARRAYSIZE(aPattern); i++) {
        aPattern[i] = 0xA5;
        abData[i] = 0xA5;
    }

    aPattern[1] = 'XX';
    aPattern[UMASK_STACK_COUNT + 1U] = 'XX';
    abData[1] = 0x31;
    abData[UMASK_STACK_COUNT + 1U] = 0x31;

    assert(abData == SearchForMaskedSignature(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern)
    ));

    abData[UMASK_STACK_COUNT + 1U] = 0x32;

    assert(NULL == SearchForMaskedSignature(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern)
    ));
}

static VOID TestAllMatches(VOID) {
    CONST BYTE abData[] = { 0x11, 0x11, 0x22, 0x22, 0x33, 0x33 };
    CONST UMASK aPattern[] = { 'XX', 'XX' };
    LPCBYTE alpMatches[3] = { NULL };

    assert(2 == SearchForMaskedSignatureAll(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern),
        alpMatches, 2
    ));
    assert(abData == alpMatches[0]);
    assert(abData + 2 == alpMatches[1]);

    assert(3 == SearchForMaskedSignatureAll(
        abData, sizeof(abData), aPattern, ARRAYSIZE(aPattern),
        alpMatches, ARRAYSIZE(alpMatches)
    ));
    assert(abData + 4 == alpMatches[2]);
}

int main(void) {
    TestNamedByteAndHighNibble();
    TestNibblePositions();
    TestUnanchoredCaptures();
    TestExistingMasks();
    TestInvalidCaptures();
    TestSignatureValidation();
    TestLargeSignature();
    TestAllMatches();

    puts("[+] SigScan64 tests passed.");
    return 0;
}
