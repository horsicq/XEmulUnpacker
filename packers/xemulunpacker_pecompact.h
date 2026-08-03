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
#ifndef XEMULUNPACKER_PECOMPACT_H
#define XEMULUNPACKER_PECOMPACT_H

#include "xemulunpacker.h"

// PECompact, x86 PE (0.90 - 2.80).
//
// XEmulUnpacker specialisation: the generic emulation engine with an OEP predicate
// (matchOEP) that recognises the PECompact stub's terminating instruction.
class XEmulUnpackerPECompact : public XEmulUnpacker {
public:
    explicit XEmulUnpackerPECompact(QObject *pParent = nullptr);

    QString getPackerName() const override;
    OPTIONS getDefaultOptions() const override;

protected:
    bool matchOEP(const OEP_CONTEXT &ctx, const OPTIONS &options) const override;
};

#endif  // XEMULUNPACKER_PECOMPACT_H
