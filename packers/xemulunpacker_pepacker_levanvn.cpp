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
#include "xemulunpacker_pepacker_levanvn.h"

XEmulUnpackerPEPackerLevanvn::XEmulUnpackerPEPackerLevanvn(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPEPackerLevanvn::getPackerName() const
{
    return QStringLiteral("PE Packer by levanvn");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPEPackerLevanvn::getDefaultOptions() const
{
    OPTIONS options;
    
    // Set a reasonable step limit to allow the unpacking loop to finish.
    options.nMaxSteps = 5000000; 
    return options;
}

bool XEmulUnpackerPEPackerLevanvn::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    // The stack must be balanced before jumping to the Original Entry Point (OEP).
    if (c.nSpDelta != 0) {
        return false;
    }

    // Pattern 1: 5-Byte 'jmp addr32' (E9) into the original section.
    if (c.bJumpToHigh && (c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    // Pattern 2: 'push imm32' (68) followed by 'ret' (C3).
    if (c.bJumpToHigh && (c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
        if (c.matchSignature(c.nPrevAddress - 5, "68........")) {
            return true;
        }
    }

    // Pattern 3: 'jmp eax' (FF E0) or 'jmp edx' (FF E2).
    // Little Endian representation: FF E0 -> 0xE0FF, FF E2 -> 0xE2FF
    if (c.bJumpToHigh && (c.nPrevSize == 2) && (c.prev16() == 0xE0FF || c.prev16() == 0xE2FF)) {
        return true;
    }

    return false;
}