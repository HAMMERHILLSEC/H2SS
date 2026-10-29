/**
 * BSD 3-Clause License
 * 
 * Copyright (c) 2026, HAMMERHILLSEC.ORG
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**/

#ifndef _HAMMERHILL_SIGSCAN_H
#define _HAMMERHILL_SIGSCAN_H

#include <Windows.h>

#include <stdlib.h>
#include <string.h>

// Bare character pairs rely on this compiler's multicharacter encoding.
static_assert(0x343F == '4?', "Unsupported multicharacter literal encoding.");

typedef WORD WORD16;
typedef WORD16 UMASK, *PUMASK;
typedef CONST UMASK* PCUMASK;

#define MASK_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define UMASK_WC ((UMASK) 0xFFFFU)
#define UMASK_STACK_COUNT 64U

/// <summary>
/// Validates a masked signature, including named-capture width consistency.
/// Does not allocate memory or read target bytes.
/// </summary>
/// <param name="Signature">Signature tokens.</param>
/// <param name="SignatureCount">Number of signature tokens.</param>
/// <returns>
/// TRUE for a nonempty, syntactically valid signature; FALSE otherwise.
/// </returns>
BOOL ValidateMaskedSignature(
    _In_reads_(SignatureCount) PCUMASK Signature,
    _In_ SIZE_T SignatureCount
);

/// <summary>
/// Finds the first masked signature. Accepts byte values, UMASK_WC, and
/// character pairs containing hex digits, '?', or named captures G-Z.
/// 'XX' captures a full byte, 'Y?' a high nibble, and '?Z' a low nibble;
/// repeated identifiers must hold equal values at every occurrence.
/// The same identifier cannot be used for both byte and nibble captures.
/// </summary>
/// <param name="SearchBase">Readable buffer to search.</param>
/// <param name="SearchSize">Buffer size in bytes.</param>
/// <param name="Signature">Signature tokens.</param>
/// <param name="SignatureCount">Number of signature tokens.</param>
/// <returns>
/// First matching address, or NULL for no match, invalid input/token,
/// or allocation failure. Patterns longer than 64 tokens use temporary storage.
/// </returns>
LPCBYTE SearchForMaskedSignature(
    _In_reads_bytes_(SearchSize) LPCVOID SearchBase,
    _In_ SIZE_T SearchSize,
    _In_reads_(SignatureCount) PCUMASK Signature,
    _In_ SIZE_T SignatureCount
);

/// <summary>
/// Finds non-overlapping matches in ascending address order.
/// Signature tokens have the same format as SearchForMaskedSignature.
/// </summary>
/// <param name="SearchBase">Readable buffer to search.</param>
/// <param name="SearchSize">Buffer size in bytes.</param>
/// <param name="Signature">Signature tokens.</param>
/// <param name="SignatureCount">Number of signature tokens.</param>
/// <param name="Matches">Output addresses; entries beyond return are untouched.</param>
/// <param name="MaxMatches">Maximum number of addresses to write.</param>
/// <returns>
/// Number of addresses written, or zero for no matches, invalid input/token,
/// or allocation failure. Patterns longer than 64 tokens use temporary storage.
/// </returns>
SIZE_T SearchForMaskedSignatureAll(
    _In_reads_bytes_(SearchSize) LPCVOID SearchBase,
    _In_ SIZE_T SearchSize,
    _In_reads_(SignatureCount) PCUMASK Signature,
    _In_ SIZE_T SignatureCount,
    _Out_writes_to_(MaxMatches, return) LPCBYTE* Matches,
    _In_ SIZE_T MaxMatches
);

#endif // _HAMMERHILL_SIGSCAN_H
