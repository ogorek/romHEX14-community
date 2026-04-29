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

/// Schema-driven decoder for Kennfeld (calibration map) records embedded
/// in OLS .ols and .kp files.
///
/// Exact port of extract_maps.py (the Python reference implementation).
/// Every field is read at the position dictated by the file's
/// format_version (== per-Kennfeld inner archive schema). No heuristic
/// scanning for scale doubles, no sentinel-based dimension guessing.
///
/// Reference: KENNFELD_RECORD_SCHEMA.md (byte-level wire schema).
class OlsKennfeldParser {
    Q_DECLARE_TR_FUNCTIONS(ols::OlsKennfeldParser)
public:
    /// Parse all Kennfeld records in [regionStart, regionEnd).
    /// @param data         Raw bytes of the entire .ols file.
    /// @param regionStart  Offset where the map region begins.
    /// @param regionEnd    Offset where the map region ends.
    /// @param schema       File format_version (== inner archive schema).
    /// @param warnings     Non-fatal issues are appended here.
    /// @return  All successfully decoded maps.
    static QVector<MapInfo> parseAll(const QByteArray &data,
                                     qsizetype regionStart,
                                     qsizetype regionEnd,
                                     int schema,
                                     QStringList *warnings = nullptr);

    /// Parse a single Kennfeld record starting at @p commentOffset.
    /// Returns a default MapInfo with name.isEmpty() on failure.
    static MapInfo parseOne(const QByteArray &data,
                            qsizetype commentOffset,
                            qsizetype hardLimit,
                            int schema);

    /// Parse the "intern" payload from a .kp file.
    static QVector<MapInfo> parseIntern(const QByteArray &internPayload,
                                        int schema,
                                        QStringList *warnings = nullptr);

    /// Locate the map region within the file.
    /// @return (start, end) offsets.
    static QPair<qsizetype, qsizetype> findMapRegion(const QByteArray &data,
                                                      int schema);

    // ── Helpers (public so free-function axis reader can use them) ────

    struct PStr {
        QString text;
        qsizetype endOffset = -1;
        bool valid() const { return endOffset >= 0; }
    };
    /// Read a CString at @p offset using schema-appropriate wire format.
    /// Schema < 439: [u32 length][bytes][NUL].
    /// Schema ≥ 439: [i32 length][bytes] (no NUL; -1/-2/-3 interned sentinels).
    static PStr readCString(const QByteArray &data, qsizetype offset,
                             int maxLen = 8192, int schema = 288);

    static uint32_t peekU32(const QByteArray &data, qsizetype off);
    static double   peekF64(const QByteArray &data, qsizetype off);

private:
    static bool isText(const char *data, int length);
    static bool isIdent(const QString &s);
};

} // namespace ols
