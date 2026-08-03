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
#include "xemulunpacker_exepack.h"

XEmulUnpackerEXEPack::XEmulUnpackerEXEPack(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerEXEPack::getPackerName() const
{
    return QStringLiteral("!EP(EXE Pack)");
}

XEmulUnpacker::OPTIONS XEmulUnpackerEXEPack::getDefaultOptions() const
{
    OPTIONS options;
    options.nMaxSteps = 20000000;
    return options;
}

bool XEmulUnpackerEXEPack::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    // !EP (EXE Pack): 2-byte 'jmp eax' (FF E0) from a higher page.
    return c.bJumpFromHigh && (c.nPrevSize == 2) && (c.prev16() == 0xE0FF);
}
