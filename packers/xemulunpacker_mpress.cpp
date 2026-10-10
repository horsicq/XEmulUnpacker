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
#include "xemulunpacker_mpress.h"

XEmulUnpackerMPRESS::XEmulUnpackerMPRESS(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerMPRESS::getPackerName() const
{
    return QStringLiteral("MPRESS");
}

XEmulUnpacker::OPTIONS XEmulUnpackerMPRESS::getDefaultOptions() const
{
    OPTIONS options;
    options.nMaxSteps = 40000000;
    // Older MPRESS (0.71-0.77, and the 32-bit stubs) jump into a SECOND loader stage in
    // written memory before the real hand-off, so the plain write-then-execute heuristic
    // stops one stage early (inside the loader) instead of at the OEP. Defer that decision so
    // the MPRESS "add esp/rsp,0x28; pop-seq; jmp OEP" tail signature (matchOEP) can win; a
    // single-stage stub (0.85+) whose first write-exec jump already is the OEP falls back to
    // the remembered candidate when no tail fires within the window.
    options.nOepDeferTailSteps = 200000;
    return options;
}

bool XEmulUnpackerMPRESS::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    // MPRESS: a 5-byte 'jmp addr32' (E9) into the image with the stack fully restored,
    // immediately preceded by the register-restore epilogue (popad / add esp,0x28 / pops).
    if ((c.nPrevSize != 5) || (c.nSpDelta != 0) || (c.prev8() != 0xE9) || !c.bCurrIsImage) {
        return false;
    }
    const quint64 nWin = c.nPrevAddress - 10;                  // 15-byte window covering the epilogue + jmp
    return c.matchSignature(nWin, "AB4883C4285E5F5B5A59")      // x64 0.71-0.97
           || c.matchSignature(nWin, "83c42841585a595b5e5f")   // x64 1.27-2.12
           || c.matchSignature(nWin, "..........AB83c42861")   // 0.77-0.97 (stosb/popad)
           || c.matchSignature(nWin, "..ab83c4285e5f5b5a59")   // 0.71-0.75
           || c.matchSignature(nWin, "....aab8........ab61");  // 1.27-2.12
}
