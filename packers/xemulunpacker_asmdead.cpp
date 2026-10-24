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
#include "xemulunpacker_asmdead.h"

XEmulUnpackerASmdead::XEmulUnpackerASmdead(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerASmdead::getPackerName() const
{
    return QStringLiteral("ASmdead");
}

XEmulUnpacker::OPTIONS XEmulUnpackerASmdead::getDefaultOptions() const
{
    OPTIONS options;
    
    // The NASM stub handles decryption, IAT resolving and relocations efficiently.
    // However, string comparisons (strcmp_ascii) during Export Directory parsing 
    // can consume a decent amount of steps.
    options.nMaxSteps = 15000000; 
    
    // The stub resides in the appended ".stub" section. Once it finishes loading 
    // the PE, it will hop back down to the original entry point.
    options.bDetectSectionHop = true;
    
    return options;
}

bool XEmulUnpackerASmdead::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // Wait until the stub jumps from its appended section down into the original image
    if (c.bJumpFromHigh && c.bCurrIsImage) {
        
        // The ASmdead NASM stub transfers control using:
        // FF E0 (jmp rax)
        if (c.nPrevSize == 2 && c.prev16() == 0xE0FF) {
            
            // Because the stub is hardcoded assembly, we can guarantee the 
            // instruction immediately preceding the jump is always `pop rbp` (5D).
            if (c.matchSignature(c.nPrevAddress - 1, "5D")) {
                return true;
            }
            
            // Fallback in case of modifications
            return true;
        }
    }

    return false;
}