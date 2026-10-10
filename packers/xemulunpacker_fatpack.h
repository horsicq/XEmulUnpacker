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
#ifndef XEMULUNPACKER_FATPACK_H
#define XEMULUNPACKER_FATPACK_H

#include "xemulunpacker.h"

class XEmulUnpackerFatpack : public XEmulUnpacker {
    Q_OBJECT
public:
    explicit XEmulUnpackerFatpack(QObject *pParent = nullptr);

    QString getPackerName() const override;
    OPTIONS getDefaultOptions() const override;
    bool matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const override;
};

#endif  // XEMULUNPACKER_FATPACK_H
