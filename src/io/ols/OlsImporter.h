/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "OlsHeader.h"
#include "OlsProjectMetadata.h"
#include "OlsVersionDirectory.h"
#include "OlsRomExtractor.h"
#include "../../romdata.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QVector>
#include <cstdint>

namespace ols {

/// One Version within an OLS project, containing its own ROM data and maps.
struct OlsVersion {
    QString          name;
    QByteArray       romData;       ///< assembled flat ROM image (byte[N] = flash addr N - baseAddress)
    QVector<OlsSegment> segments;   ///< raw per-segment chunks
    QVector<MapInfo> maps;          ///< decoded Kennfeld records (addresses translated to ROM offsets)
    ByteOrder        byteOrder = ByteOrder::BigEndian;
    uint32_t         baseAddress = 0;  ///< minimum flash base; romData[0] = this address
};

/// Result returned by OlsImporter::importFromBytes().
struct OlsImportResult {
    OlsHeader              header;
    OlsProjectMetadata     metadata;
    QVector<OlsVersion>    versions;   ///< 1..N Versions
    QString                error;      ///< empty on success
    QStringList            warnings;   ///< non-fatal issues
};

/// Top-level facade for importing OLS .ols files.
///
/// Single entry point: importFromBytes().  The pipeline is:
///   1. OlsHeader::parse()          -- 24-byte header validation
///   2. OlsMagicScanner::scan()     -- locate M1..M7 anchors
///   3. OlsProjectMetadata::parse() -- 32 project-metadata fields
///   4. OlsVersionDirectory::parse()-- per-Version directory
///   5. OlsRomExtractor::extractAll() -- schema-driven ROM segments
///   6. OlsKennfeldParser::parseAll() -- schema-driven map records
///
/// Each stage produces structured results; non-fatal issues are collected
/// in warnings.
class OlsImporter {
    Q_DECLARE_TR_FUNCTIONS(ols::OlsImporter)
public:
    /// Import an .ols file from raw bytes.
    /// @param fileData  Entire .ols file contents.
    /// @return  Import result; check .error for failures.
    static OlsImportResult importFromBytes(const QByteArray &fileData);
};

} // namespace ols
