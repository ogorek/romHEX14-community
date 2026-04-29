/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>
#include <cstdint>

namespace ols {

class CArchiveReader;

/// One entry in the per-Version directory.  Each Version has its own
/// Make/Model/Type strings and the offset/size information needed to
/// locate its ROM segment payload.
struct OlsVersionSlot {
    int      index = -1;
    qsizetype slotFileOffset = 0;   // absolute file offset of this slot
    // Per-slot fields parsed from the Serialize schema
    // (the full slot is versionRecordSize bytes — we only extract what
    //  the ROM extractor needs; the rest is opaque for now)
};

/// The Version-directory header parsed from M3 - 12.
///
/// Layout (from OLS_LOAD_WRAPPER.md line 1163-1167):
///   Seek(anchorM3 - 12)
///   u32 numVersions_minus_1
///   u32 versionDataStart   (absolute file offset of slot #0 prefix)
///   u32 versionRecordSize  (bytes per slot)
///   magic 0x42007899       (the M3 anchor itself)
///
/// Sanity invariant: versionDataStart + 4 + versionRecordSize * numVersions == fileSize
struct OlsVersionDirectory {
    uint32_t numVersions       = 0;
    uint32_t versionDataStart  = 0;
    uint32_t versionRecordSize = 0;

    QVector<OlsVersionSlot> versionSlots;

    /// Returns the absolute file offset of the i-th Version slot.
    qsizetype slotOffset(int i) const {
        return static_cast<qsizetype>(versionDataStart) + 4
             + static_cast<qsizetype>(versionRecordSize) * i;
    }

    /// Locate the M3 anchor (0x42007899) in the first ~2 KB preamble,
    /// then parse the 3 u32 directory header and build the slot list.
    ///
    /// @param fileData  the entire .ols file contents
    /// @param warnings  non-fatal issues (e.g. sanity mismatch)
    /// @return  populated directory; numVersions == 0 on failure
    static OlsVersionDirectory parse(const QByteArray &fileData,
                                     QStringList *warnings = nullptr);
};

} // namespace ols
