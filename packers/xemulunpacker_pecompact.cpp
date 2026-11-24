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
    // PECompact 2.9x (e.g. 2.96.2) commonly uses LZMA codecs which need more steps than 1.x/aPLib.
    options.nMaxSteps = 120000000;
    return options;
}

bool XEmulUnpackerPECompact::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    if (c.nSpDelta != 0) {
        return false;
    }

    if (c.bJumpFromHigh) {
        // 1.00-1.10 'ret' (C3); 1.50-1.76 'ret 4' (C2 04 00); 2.x 'jmp eax' (FF E0).
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

    // 0.90: 'ret' (C3) or 2.x loader: 'jmp eax' (FF E0) from a VirtualAlloc heap buffer into the image.
    if (c.bPrevIsHeap && c.bCurrIsImage) {
        if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
            return true;
        }
        if ((c.nPrevSize == 2) && (c.prev16() == 0xE0FF)) {
            return true;
        }
    }

    // 2.xx (including 2.96.2) fallback if the tail stub executes in the same section as OEP:
    // After VirtualFree, PECompact 2.x computes OEP via `mov eax, [esi+0Ch]; add eax, ...` (8B 46 0C 03)
    // shortly before transferring control with `jmp eax` (FF E0).
    if (c.bCurrIsImage && (c.nPrevSize == 2) && (c.prev16() == 0xE0FF) && (c.nPrevAddress >= 32)) {
        for (quint64 nOff = 4; nOff <= 32; nOff++) {
            if (c.matchSignature(c.nPrevAddress - nOff, "8B460C03")) {
                return true;
            }
        }
    }

    return false;
}