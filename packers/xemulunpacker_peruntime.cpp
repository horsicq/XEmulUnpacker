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
#include "xemulunpacker_peruntime.h"

XEmulUnpackerPERuntime::XEmulUnpackerPERuntime(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPERuntime::getPackerName() const
{
    return QStringLiteral("PE Runtime Packer");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPERuntime::getDefaultOptions() const
{
    OPTIONS options;
    
    // The packer uses a very tight single-byte XOR loop.
    // A 10MB section would require ~40-50M instructions, so we set a generous limit.
    options.nMaxSteps = 50000000; 
    
    // The stub is appended as a new section at the end of the file.
    // Once the XOR loop finishes, it jumps back down to the original entry point.
    options.bDetectSectionHop = true;
    
    return options;
}

bool XEmulUnpackerPERuntime::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // Check if we are jumping from the appended stub back down into the original image
    if (c.bJumpFromHigh && c.bCurrIsImage) {
        
        // The PE Runtime Packer uses the following instruction to jump to OEP:
        // 0xFF 0xE1 (jmp rcx)
        if (c.nPrevSize == 2 && c.prev16() == 0xE1FF) {
            
            // To be absolutely certain, we can verify the preceding instruction.
            // The packer loads the OEP into RCX just before the jump using:
            // 48 8D 88 [4 bytes offset]  (lea rcx, [rax + ORIG_ENTRY])
            if (c.matchSignature(c.nPrevAddress - 7, "488D88........")) {
                return true;
            }
            
            // Fallback in case the signature check failed but the jump is correct
            return true;
        }
    }

    return false;
}