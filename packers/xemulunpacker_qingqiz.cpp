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
#include "xemulunpacker_qingqiz.h"

XEmulUnpackerQingQiz::XEmulUnpackerQingQiz(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerQingQiz::getPackerName() const
{
    return QStringLiteral("QingQiz");
}

XEmulUnpacker::OPTIONS XEmulUnpackerQingQiz::getDefaultOptions() const
{
    OPTIONS options;
    
    // The stub parses the entire IAT, processes base relocations, and 
    // decodes the target section. We need a decent amount of steps.
    options.nMaxSteps = 10000000; 
    
    // The unpacked PE is loaded into newly allocated memory (VirtualAlloc).
    // XVolkolak will naturally detect execution transferring to this region.
    options.bDetectWriteExec = true;
    
    return options;
}

bool XEmulUnpackerQingQiz::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // Wait until execution jumps into a newly allocated region (not a valid image section)
    if (!c.bCurrIsImage) {
        
        // The jump to OEP is compiled from a C++ function pointer call:
        // (reinterpret_cast<void(*)()>(enter_addr))();
        // This generally translates to a CALL or JMP to a register.
        
        if (c.nPrevSize == 2) {
            quint16 opcode = c.prev16();
            
            // Check for CALL to register (FF D0 ... FF D7)
            // e.g., FF D0 = call eax / call rax
            if (opcode >= 0xD0FF && opcode <= 0xD7FF) {
                return true;
            }
            
            // Check for JMP to register (FF E0 ... FF E7)
            // (If the compiler optimized the call into a tail-jump)
            if (opcode >= 0xE0FF && opcode <= 0xE7FF) {
                return true;
            }
        }
    }

    return false;
}