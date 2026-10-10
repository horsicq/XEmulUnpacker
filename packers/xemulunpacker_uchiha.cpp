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
#include "xemulunpacker_uchiha.h"

XEmulUnpackerUchiha::XEmulUnpackerUchiha(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerUchiha::getPackerName() const
{
    return QStringLiteral("Uchiha");
}

XEmulUnpacker::OPTIONS XEmulUnpackerUchiha::getDefaultOptions() const
{
    OPTIONS options;
    // aPLib decompression and dynamic IAT resolving loops.
    // 10,000,000 steps are completely sufficient for this lightweight logic.
    options.nMaxSteps = 10000000;
    return options;
}

bool XEmulUnpackerUchiha::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // Uchiha strictly targets 32-bit (x86) executables.
    if (c.bIs64) {
        return false;
    }

    // Uchiha generates the final JMP dynamically via C++ after resolving the IAT.
    // The exact generated sequence before the final jump is:
    // 80 B9 XX XX XX XX 00   -> CMP BYTE PTR DS:[posName + ECX], 0
    // 0F 85 XX XX XX XX      -> JNE (6 bytes)
    // E9 XX XX XX XX         -> JMP OEP (5 bytes)

    // Check if the current instruction is the 5-byte relative JMP to OEP
    if (c.nPrevSize == 5 && c.prev8() == 0xE9) {
        // Look exactly 6 bytes backwards to see if it was preceded by the JNE
        if (c.matchSignature(c.nPrevAddress - 6, "0F85")) {
            return true;
        }
    }

    return false;
}
