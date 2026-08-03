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
#ifndef XEMUUNPACK_H
#define XEMUUNPACK_H

#include <QByteArray>
#include <QString>

#include "xemuemulator.h"

// Thin backwards-compatible wrapper around XEmulUnpacker. New code should
// use XEmulUnpacker directly (it is stateful, emits progress/diagnostic
// signals and returns a richer result); this façade is kept for the existing
// static-call sites.
class XEmuUnpack {
public:
    struct RESULT {
        bool bSuccess;
        quint64 nOEP;        // recovered original entry point (RVA)
        quint64 nImageBase;
        qint64 nSteps;       // instructions executed
        QByteArray baPE;     // rebuilt PE (valid only if bSuccess)
        QString sReason;     // stop reason / diagnostics
    };

    struct OPTIONS {
        qint64 nMaxSteps;
        bool bLoadDependencies;
        QString sSystemRoot;

        OPTIONS() : nMaxSteps(20000000), bLoadDependencies(false)
        {
        }
    };

    static RESULT unpackFile(const QString &sFileName, const OPTIONS &options = OPTIONS());
};

#endif  // XEMUUNPACK_H
