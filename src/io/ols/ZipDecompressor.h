/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QString>

namespace ols {

/// Thin wrapper around ZLIB inflate for decompressing raw-deflate streams.
/// Used to decompress the "intern" entry inside .kp files.
class ZipDecompressor {
public:
    /// Inflate a raw-deflate compressed buffer (no zlib/gzip header).
    /// Uses inflateInit2 with -MAX_WBITS for raw deflate.
    /// @param compressed  The compressed data bytes.
    /// @param err         Optional error string populated on failure.
    /// @return  The decompressed bytes, or an empty QByteArray on error.
    static QByteArray decompress(const QByteArray &compressed,
                                 QString *err = nullptr);

    /// Inflate with a known uncompressed size hint (avoids reallocation).
    static QByteArray decompress(const QByteArray &compressed,
                                 qsizetype expectedSize,
                                 QString *err = nullptr);
};

} // namespace ols
