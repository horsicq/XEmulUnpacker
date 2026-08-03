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
#include "xemulunpacker_winupack.h"

XEmulUnpackerWinupack::XEmulUnpackerWinupack(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerWinupack::getPackerName() const
{
    return QStringLiteral("(Win)Upack");
}

XEmulUnpacker::OPTIONS XEmulUnpackerWinupack::getDefaultOptions() const
{
    OPTIONS options;
    options.nMaxSteps = 40000000;
    return options;
}

bool XEmulUnpackerWinupack::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    if (!c.bJumpFromHigh || (c.nSpDelta != 0)) {
        return false;
    }
    // (Win)Upack: 'ret' (C3); 0.29-0.32 6-byte 'je' (0F 84); Alt stub 5-byte 'jmp' (E9).
    if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
        return true;
    }
    if ((c.nPrevSize == 6) && (c.prev16() == 0x840F)) {
        return true;
    }
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }
    return false;
}
