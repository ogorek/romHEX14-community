/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <QString>
#include <QStringList>
#include <cstdint>

namespace ols {

class CArchiveReader;

/// All project-metadata fields parsed from the  block
/// starting at file offset 0x18.  Field names match the Python reference
/// parser (parse_ols.py) and OLS_LOAD_WRAPPER.md schema table.
struct OlsProjectMetadata {
    // ── Always-read fields (16 CStrings + 1 u64 + 7 more CStrings) ─────
    QString make;                  // "Seat"
    QString model;                 // "Leon"
    QString type;                  // "(DAMOS)"
    QString year;
    QString outputKwPs;
    QString cylinders;
    QString country;
    QString drivetrain;
    QString memory;                // "Eprom"
    QString manufacturer;          // "Bosch"
    QString ecuName;               // "MED17.5.20"
    QString hwNumber;              // "03C906022J "
    QString swNumber;              // "0261S04137"
    QString productionNo;          // "505704"
    QString engineCode;
    QString transmission;
    uint64_t lastWriteTime = 0;    // FILETIME (100-ns ticks since 1601-01-01)
    QString originalFileName;      // "5039.ols"
    QString olsVersionString;   // "OLS 5.0 (Windows)"
    QString reserved2;
    QString revisionTag;           // "0 (Original)"
    QString reserved3;
    QString reserved4;
    QString reserved5;

    // ── Schema-gated fields ─────────────────────────────────────────────
    QString  baseAddressHex;       // minVer 0x6E  "2F0000"
    uint32_t buildNumber = 0;      // minVer 0x30
    uint64_t checksum = 0;         // minVer 0x34
    uint32_t flags = 0;            // minVer 0x38
    QString  importComment;        // minVer 0x3E
    uint32_t postCommentFlag = 0;  // minVer 0x3F
    QString  tag;                  // minVer 0x40  (often == swNumber)
    uint32_t regionCount = 0;      // minVer 0x4F
    QString  notes;                // minVer 0x55

    // ── Parse from archive ──────────────────────────────────────────────
    /// Parse the project metadata block starting at the reader's current
    /// position (normally 0x18).  Returns the populated struct; non-fatal
    /// issues are appended to @p warnings.
    static OlsProjectMetadata parse(CArchiveReader &reader,
                                    QStringList *warnings = nullptr);
};

} // namespace ols
