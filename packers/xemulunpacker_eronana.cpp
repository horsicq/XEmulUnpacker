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
#include "xemulunpacker_eronana.h"

XEmulUnpackerEronana::XEmulUnpackerEronana(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerEronana::getPackerName() const
{
    return QStringLiteral("Eronana Packer");
}

XEmulUnpacker::OPTIONS XEmulUnpackerEronana::getDefaultOptions() const
{
    OPTIONS options;
    // Eronana Packer utilizes a custom compression loop and manual IAT reconstruction.
    // 15,000,000 steps remain a solid upper bound to ensure complete execution.
    options.nMaxSteps = 15000000; 
    return options;
}

bool XEmulUnpackerEronana::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    // x86 only!
    if (c.bIs64) {
        return false;
    }

    // The packer uses a highly specific tail-jump technique to preserve the OEP 
    // address after calling POPAD. 
    // 
    // The exact byte sequence is:
    // 0x61             -> POPAD
    // 0xFF 0x65 0xFC   -> JMP [EBP-4]

    // Check if the final jump instruction is exactly 3 bytes long (FF 65 FC)
    if (c.nPrevSize == 3) {
        // Match the JMP [EBP-4] instruction
        if (c.matchSignature(c.nPrevAddress - 3, "FF65FC")) {
            // Confirm it was immediately preceded by POPAD (0x61)
            if (c.matchSignature(c.nPrevAddress - 4, "61")) {
                return true;
            }
        }
    }

    // Fallback pattern: Direct relative 5-byte jump (E9 XX XX XX XX)
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    return false;
}