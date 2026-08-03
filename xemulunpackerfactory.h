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
#ifndef XEMULUNPACKERFACTORY_H
#define XEMULUNPACKERFACTORY_H

#include <QObject>
#include <QString>
#include <QStringList>

#include "xemulunpacker.h"

// Registry / factory for the packer-specific XEmulUnpacker subclasses.
//
// Lets a front end enumerate the known packer families and instantiate the right
// unpacker by name without depending on every packer header. The special entry
// "Generic (auto)" maps to the base XEmulUnpacker (heuristic OEP detection, no
// packer signature).
class XEmulUnpackerFactory {
public:
    // Sentinel name for the generic, packer-agnostic unpacker.
    static QString genericName();

    // All selectable unpackers, generic first, then one per packer family. The
    // packer entries are exactly the values returned by each subclass's
    // getPackerName(), so a name round-trips through create().
    static QStringList packerNames();

    // Create the unpacker for sPackerName. genericName(), an empty string or any
    // unknown name yields the base XEmulUnpacker; a known packer name yields its
    // subclass. Never returns nullptr. The caller owns the returned object.
    static XEmulUnpacker *create(const QString &sPackerName, QObject *pParent = nullptr);
};

#endif  // XEMULUNPACKERFACTORY_H
