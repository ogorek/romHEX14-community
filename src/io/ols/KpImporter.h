/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "../../romdata.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QVector>
#include <cstdint>

namespace ols {

/// Result of importing a .kp (Kennfeldpaket / map package) file.
struct KpImportResult {
    uint32_t       formatVersion = 0;
    uint32_t       declaredFileSize = 0;
    uint32_t       mapCount = 0;
    QVector<MapInfo> maps;
    QString        error;        ///< empty on success
    QStringList    warnings;     ///< non-fatal issues
};

/// Imports .kp files (OLS map packages).
///
/// A .kp file is a OLS project file containing an embedded PKZIP archive
/// with a single entry named "intern".  The intern payload contains the
/// Kennfeld (calibration map) records in the same format used by .ols files.
///
/// Reference: KP_FORMAT.md and parse_kp.py.
class KpImporter {
    Q_DECLARE_TR_FUNCTIONS(ols::KpImporter)
public:
    /// Import maps from a .kp file's raw bytes.
    /// @param fileData    Entire .kp file contents.
    /// @param baseAddress ROM base address for address translation.
    /// @return  Import result with maps and any error/warnings.
    static KpImportResult importFromBytes(const QByteArray &fileData,
                                           uint32_t baseAddress = 0);

private:
    /// Locate and extract the PKZIP "intern" entry from the file data.
    /// @param fileData  Entire file bytes.
    /// @param compressed  Output: raw compressed bytes of the intern entry.
    /// @param uncompressedSize  Output: declared uncompressed size.
    /// @param method      Output: ZIP compression method (0=store, 8=deflate).
    /// @param err         Output: error message on failure.
    /// @return  true on success.
    static bool extractInternEntry(const QByteArray &fileData,
                                    QByteArray &compressed,
                                    uint32_t &uncompressedSize,
                                    uint16_t &method,
                                    QString &err);
};

} // namespace ols
