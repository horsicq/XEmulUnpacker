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
#include "xemulunpacker_petite.h"

XEmulUnpackerPetite::XEmulUnpackerPetite(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPetite::getPackerName() const
{
    return QStringLiteral("Petite");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPetite::getDefaultOptions() const
{
    OPTIONS options;
    options.nMaxSteps = 40000000;
    return options;
}

bool XEmulUnpackerPetite::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    if (c.nSpDelta != 0) {
        return false;
    }
    // Petite 2.4: 3-byte 'jmp dword [eax+0x20]' (FF 60 20), jumping up into the image.
    if (c.bJumpToHigh && (c.nPrevSize == 3) && ((c.prev32() & 0xFFFFFF) == 0x2060FF)) {
        return true;
    }
    // Petite 1.2-1.4 / 2.2-2.3: 5-byte 'jmp addr32' (E9) preceded by 'popa/popf' (66 9D).
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        if (c.matchSignature(c.nPrevAddress - 5, "......669D") || c.matchSignature(c.nPrevAddress - 5, "669D83c4..")) {
            return true;
        }
    }
    return false;
}
