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
#ifndef XEMULUNPACKER_NPACK_H
#define XEMULUNPACKER_NPACK_H

#include "xemulunpacker.h"

// nPack, x86 PE.
//
// XEmulUnpacker specialisation: the generic emulation engine with an OEP predicate
// (matchOEP) that recognises the nPack stub's terminating instruction.
class XEmulUnpackerNPack : public XEmulUnpacker {
public:
    explicit XEmulUnpackerNPack(QObject *pParent = nullptr);

    QString getPackerName() const override;
    OPTIONS getDefaultOptions() const override;

protected:
    bool matchOEP(const OEP_CONTEXT &ctx, const OPTIONS &options) const override;

    // Recover the stored absolute OEP from the stub's `add [P],eax; push [P]; ret` tail when the
    // (larger bcb) image faults in the aPLib depacker before that ret retires and matchOEP fires.
    quint64 recoverOepAtStop(XEmuMemoryManager *pMemoryManager, quint64 nScanStart, quint64 nScanEnd, quint64 nImageBase, quint64 nImageSize) const override;
};

#endif  // XEMULUNPACKER_NPACK_H
