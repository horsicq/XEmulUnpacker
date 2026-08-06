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
#include "xemulunpacker_themida.h"

XEmulUnpackerThemida::XEmulUnpackerThemida(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerThemida::getPackerName() const
{
    return QStringLiteral("Themida");
}

XEmulUnpacker::OPTIONS XEmulUnpackerThemida::getDefaultOptions() const
{
    OPTIONS options;
    // Themida uses advanced protection/VM routines.
    // Finding the OEP requires a significantly higher amount of max steps.
    options.nMaxSteps = 100000000; 
    return options;
}

bool XEmulUnpackerThemida::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    if (c.nSpDelta != 0) {
        return false;
    }

    // Pattern 1: 5-byte 'call addr32' (E8) or 'jmp addr32' (E9) jumping to the Original Entry Point
    if (c.bJumpToHigh && (c.nPrevSize == 5) && (c.prev8() == 0xE8 || c.prev8() == 0xE9)) {
        return true;
    }

    // Pattern 2: 'push imm32' (68) followed by 'ret' (C3) jumping to the OEP
    if (c.bJumpToHigh && (c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
        if (c.matchSignature(c.nPrevAddress - 5, "68........")) {
            return true;
        }
    }

    // Pattern 3: 'mov eax, imm32' (B8) followed by 'jmp eax' (FF E0) or 'call eax' (FF D0)
    // In Little Endian: FF E0 -> 0xE0FF, FF D0 -> 0xD0FF
    if (c.bJumpToHigh && (c.nPrevSize == 2) && (c.prev16() == 0xE0FF || c.prev16() == 0xD0FF)) {
        if (c.matchSignature(c.nPrevAddress - 5, "B8........")) {
            return true;
        }
    }

    return false;
}
