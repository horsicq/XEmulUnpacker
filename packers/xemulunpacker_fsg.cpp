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
#include "xemulunpacker_fsg.h"

XEmulUnpackerFSG::XEmulUnpackerFSG(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerFSG::getPackerName() const
{
    return QStringLiteral("FSG");
}

XEmulUnpacker::OPTIONS XEmulUnpackerFSG::getDefaultOptions() const
{
    OPTIONS options;
    options.nMaxSteps = 20000000;
    return options;
}

bool XEmulUnpackerFSG::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    // FSG 2.00: 'jmp dword [ebx+0xc]' (FF 63 0C) executed from the PE header page.
    if (c.bJumpFromHeader && (c.nPrevSize == 3) && (c.nSpDelta == 0) && ((c.prev32() & 0xFFFFFF) == 0x0C63FF)) {
        return true;
    }
    // FSG 1.00-1.33: 6-byte 'je' (0F 84) from a higher page.
    if (c.bJumpFromHigh && (c.nPrevSize == 6) && (c.nSpDelta == 0) && (c.prev16() == 0x840F)) {
        return true;
    }
    return false;
}
