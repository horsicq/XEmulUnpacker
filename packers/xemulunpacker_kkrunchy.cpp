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
#include "xemulunpacker_kkrunchy.h"

XEmulUnpackerKKrunchy::XEmulUnpackerKKrunchy(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerKKrunchy::getPackerName() const
{
    return QStringLiteral("kkrunchy");
}

XEmulUnpacker::OPTIONS XEmulUnpackerKKrunchy::getDefaultOptions() const
{
    OPTIONS options;
    // kkrunchy's MMX arithmetic-coder decompressor is per-symbol heavy: the 0.23a2+ line
    // needs ~42M instructions to reach the OEP, so give it generous headroom.
    options.nMaxSteps = 120000000;
    return options;
}

bool XEmulUnpackerKKrunchy::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    if (!c.bJumpToHigh || (c.nSpDelta != 0)) {
        return false;
    }
    // kkrunchy 0.23a: 6-byte 'je' (0F 84) followed by 'xor eax,eax' (31 C0) or 'lodsb/cmp' (AC 3C FF).
    if ((c.nPrevSize == 6) && (c.prev16() == 0x840F)) {
        if (c.matchSignature(c.nPrevAddress, "0f84........31c0") || c.matchSignature(c.nPrevAddress, "0f84........ac3cff")) {
            return true;
        }
    }
    // Older: 5-byte 'jmp addr32' (E9).
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }
    return false;
}
