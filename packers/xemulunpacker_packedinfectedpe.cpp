/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xemulunpacker_packedinfectedpe.h"

XEmulUnpackerPackedInfectedPE::XEmulUnpackerPackedInfectedPE(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPackedInfectedPE::getPackerName() const
{
    return QStringLiteral("Packed-Infected-PE");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPackedInfectedPE::getDefaultOptions() const
{
    OPTIONS options;
    // Step limit to allow anti-debug checks, CPUID VM checks, API resolution, and the XOR loop to finish.
    options.nMaxSteps = 10000000; 
    return options;
}

bool XEmulUnpackerPackedInfectedPE::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    // The stack must be balanced before jumping to the Original Entry Point.
    if (c.nSpDelta != 0) {
        return false;
    }

    // The jump must lead to the original high memory / section.
    if (!c.bJumpToHigh) {
        return false;
    }

    // Pattern 1: Standard 5-byte relative jump (E9) patched via adjustUnpack for the OEP transfer.
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    // Pattern 2: 'push imm32' (68) followed by 'ret' (C3).
    if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
        if (c.matchSignature(c.nPrevAddress - 5, "68........")) {
            return true;
        }
    }

    return false;
}