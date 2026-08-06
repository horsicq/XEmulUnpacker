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
#include "xemulunpacker_alushpacker.h"

XEmulUnpackerAlushPacker::XEmulUnpackerAlushPacker(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerAlushPacker::getPackerName() const
{
    return QStringLiteral("AlushPacker");
}

XEmulUnpacker::OPTIONS XEmulUnpackerAlushPacker::getDefaultOptions() const
{
    OPTIONS options;
    // AlushPacker uses XTEA block decryption, LZAV decompression, resolves imports 
    // (including binary searches for forwarded exports), and handles Relocations/TLS.
    // This requires an exceptionally high step limit to prevent emulation timeouts.
    options.nMaxSteps = 50000000; 
    return options;
}

bool XEmulUnpackerAlushPacker::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    // AlushPacker is a manual mapper that dynamically allocates memory (via VirtualAlloc)
    // for the uncompressed/decrypted payload. The jump to OEP or the first TLS Callback 
    // MUST point outside the original stub into this high memory area.
    if (!c.bJumpToHigh) {
        return false;
    }

    // Pattern 1: 'call reg' (indirect call via standard register)
    // Opcodes: FF D0 to FF D7
    if ((c.nPrevSize >= 2) && (c.prev16() >= 0xD0FF && c.prev16() <= 0xD7FF)) {
        return true;
    }

    // Pattern 2: 'jmp reg' (indirect jump via standard register)
    // Opcodes: FF E0 to FF E7
    if ((c.nPrevSize >= 2) && (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF)) {
        return true;
    }

    // Additional checks specifically for x64 architecture
    if (c.bIs64) {
        // Pattern 3: REX-prefixed 'call reg' or 'jmp reg' for extended x64 registers (R8-R15)
        // Opcodes: 41 FF D0 (call r8) or 41 FF E0 (jmp r8)
        if (c.nPrevSize >= 3) {
            if (c.matchSignature(c.nPrevAddress - c.nPrevSize, "41FFD?")) {
                return true;
            }
            if (c.matchSignature(c.nPrevAddress - c.nPrevSize, "41FFE?")) {
                return true;
            }
        }
    }

    return false;
}