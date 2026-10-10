/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * ...
 */
#include "xemulunpacker_pinkiepie.h"

XEmulUnpackerPinkiePie::XEmulUnpackerPinkiePie(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPinkiePie::getPackerName() const
{
    return QStringLiteral("pinkie-pie");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPinkiePie::getDefaultOptions() const
{
    OPTIONS options;
    // The packer uses a very fast XOR loop and a short polymorphic math engine
    // to calculate API calls and the OEP. It's extremely lightweight.
    // 5,000,000 steps are more than enough to fully emulate the .kucd section.
    options.nMaxSteps = 5000000;
    return options;
}

bool XEmulUnpackerPinkiePie::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // This packer ONLY supports 32-bit (x86) binaries.
    if (c.bIs64) {
        return false;
    }

    // The packer modifies the existing PE file by appending a '.kucd' section
    // and XOR-decrypting the original code section in-place.
    // It does not allocate dynamic high-memory via VirtualAlloc.
    if (c.bJumpToHigh) {
        return false;
    }

    // Since the stub cleans up after itself before transferring execution back
    // to the original code section, the stack must be balanced.
    if (c.nSpDelta != 0) {
        return false;
    }

    // According to the provided 'shellcode.cpp', the polymorphic engine uses arithmetic
    // (ADD, SUB, XOR) to dynamically calculate the OEP address specifically inside the
    // EAX register. After calculation, execution is transferred to this register.

    // Pattern 1: Indirect jump via register (most likely 'jmp eax')
    // Opcodes: FF E0 to FF E7 -> Little Endian: 0xE0FF to 0xE7FF
    if ((c.nPrevSize == 2) && (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF)) {
        return true;
    }

    // Pattern 2: Push register and return (e.g., 'push eax' followed by 'ret')
    // Opcodes: 50 (push eax) to 57 (push edi), followed by C3 (ret)
    if (c.nPrevSize == 1 && c.prev8() == 0xC3) {
        if (c.matchSignature(c.nPrevAddress - 1, "5?")) {
            return true;
        }
    }

    // Pattern 3: Standard relative jump (E9 XX XX XX XX)
    // Included as a fallback in case the 'crypt_end' stub uses a direct relative tail-jump
    // instead of an indirect register jump after adding the ImageBase.
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    return false;
}
