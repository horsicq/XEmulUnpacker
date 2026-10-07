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
#include "xemulunpacker_permafrost.h"

XEmulUnpackerPermafrost::XEmulUnpackerPermafrost(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPermafrost::getPackerName() const
{
    return QStringLiteral("permafrost");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPermafrost::getDefaultOptions() const
{
    OPTIONS options;
    
    // The unshuffle process is relatively fast (O(N) based on block count).
    // A mid-range step limit is sufficient to sort even a large .text section.
    options.nMaxSteps = 5000000; 
    
    // Permafrost unpacks entirely within the .text section (code cave), 
    // so we disable section hop detection to prevent false negatives.
    options.bDetectSectionHop = false;
    
    return options;
}

bool XEmulUnpackerPermafrost::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // The final instruction is always a 'JMP RAX' (FF E0) 
    if (c.nPrevSize == 2 && c.prev16() == 0xE0FF) {
        
        // Scenario 1: Standard Mode
        // Looks for: LEA RAX, [RBX + offset] -> 48 8D 83 ?? ?? ?? ??
        if (c.matchSignature(c.nPrevAddress - 7, "488D83........")) {
            return true;
        }
        
        // Scenario 2: TLS Mode
        // Looks for the POP sequence preceding the JMP RAX: 
        // POP R8, POP RDX, POP RCX, POP RDI, POP RSI, POP RBP, POP RBX
        // -> 41 58 5A 59 5F 5E 5D 5B
        if (c.matchSignature(c.nPrevAddress - 8, "41585A595F5E5D5B")) {
            return true;
        }
    }

    return false;
}