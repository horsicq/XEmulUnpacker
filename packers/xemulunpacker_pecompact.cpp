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
#include "xemulunpacker_pecompact.h"

XEmulUnpackerPECompact::XEmulUnpackerPECompact(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPECompact::getPackerName() const
{
    return QStringLiteral("PECompact");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPECompact::getDefaultOptions() const
{
    OPTIONS options;
    // PECompact 2.9x/3.x (e.g. 3.00.2) commonly uses LZMA/LZMA2 codecs.
    options.nMaxSteps = 150000000;
    // Required for PEC2TO / merged-section builds (only .text + .rsrc) where
    // both the stub and the unpacked OEP reside inside .text (same-section W^X hop).
    options.bDetectWriteExec = true;
    return options;
}

bool XEmulUnpackerPECompact::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    if (c.nSpDelta != 0) {
        return false;
    }

    if (c.bJumpFromHigh) {
        // 1.00-1.10 'ret' (C3); 1.50-1.76 'ret 4' (C2 04 00); 2.x/3.x 'jmp eax' (FF E0).
        if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
            return true;
        }
        if ((c.nPrevSize == 3) && ((c.prev32() & 0xFFFFFF) == 0x0004C2)) {
            return true;
        }
        if ((c.nPrevSize == 2) && (c.prev16() == 0xE0FF)) {
            return true;
        }
    }

    // 0.90 'ret' (C3) or 2.x/3.x loader 'jmp eax' (FF E0) from a VirtualAlloc heap buffer into the image.
    if (c.bPrevIsHeap && c.bCurrIsImage) {
        if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
            return true;
        }
        if ((c.nPrevSize == 2) && (c.prev16() == 0xE0FF)) {
            return true;
        }
    }

    // PECompact 2.9x / 3.x (e.g. 3.00.2 PEC2TO) where the stub resides in .text itself
    // and jumps into freshly decompressed code in the same section (triggered via bDetectWriteExec).
    if (c.bCurrIsImage) {
        // Tail jump via 'jmp eax' (FF E0)
        if ((c.nPrevSize == 2) && (c.prev16() == 0xE0FF)) {
            return true;
        }

        // Tail jump via 'push eax; ret' (50 C3) or 'push imm32; ret' (68 .. .. .. .. C3)
        if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
            if ((c.nPrevAddress >= 1) && c.matchSignature(c.nPrevAddress - 1, "50C3")) {
                return true;
            }
            if ((c.nPrevAddress >= 5) && c.matchSignature(c.nPrevAddress - 5, "68........C3")) {
                return true;
            }
        }

        // Direct patched tail jump 'jmp rel32' (E9 ..)
        if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
            return true;
        }
    }

    return false;
}