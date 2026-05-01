/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "KpImporter.h"
#include "OlsKennfeldParser.h"
#include "ZipDecompressor.h"

#include <QtEndian>
#include <cstring>

namespace ols {

// ── PKZIP local file header extraction ─────────────────────────────────────
// Reference: parse_kp.py parse_zip() lines ~192-234.

bool KpImporter::extractInternEntry(const QByteArray &fileData,
                                     QByteArray &compressed,
                                     uint32_t &uncompressedSize,
                                     uint16_t &method,
                                     QString &err)
{
    // Find PK\x03\x04 (local file header signature)
    static const char pkSig[] = { 'P', 'K', '\x03', '\x04' };
    int lfhOff = -1;
    for (qsizetype i = 0; i + 4 <= fileData.size(); ++i) {
        if (std::memcmp(fileData.constData() + i, pkSig, 4) == 0) {
            lfhOff = static_cast<int>(i);
            break;
        }
    }
    if (lfhOff < 0) {
        err = KpImporter::tr("No PKZIP local file header (PK\\x03\\x04) found");
        return false;
    }

    // Local file header is 30 bytes:
    //   0: u32 signature (PK\x03\x04)
    //   4: u16 version needed
    //   6: u16 general purpose flag
    //   8: u16 compression method
    //  10: u16 last mod time
    //  12: u16 last mod date
    //  14: u32 CRC-32
    //  18: u32 compressed size
    //  22: u32 uncompressed size
    //  26: u16 filename length
    //  28: u16 extra field length
    //  30: filename + extra field + compressed data
    if (lfhOff + 30 > fileData.size()) {
        err = KpImporter::tr("Truncated ZIP local file header");
        return false;
    }

    const auto *h = reinterpret_cast<const uchar *>(
        fileData.constData() + lfhOff);

    method = qFromLittleEndian<uint16_t>(h + 8);
    uint32_t csize = qFromLittleEndian<uint32_t>(h + 18);
    uncompressedSize = qFromLittleEndian<uint32_t>(h + 22);
    uint16_t fnLen = qFromLittleEndian<uint16_t>(h + 26);
    uint16_t extraLen = qFromLittleEndian<uint16_t>(h + 28);

    // Verify the filename is "intern"
    qsizetype fnStart = lfhOff + 30;
    if (fnStart + fnLen > fileData.size()) {
        err = KpImporter::tr("Truncated ZIP filename");
        return false;
    }
    QString filename = QString::fromLatin1(
        fileData.constData() + fnStart, fnLen);
    if (filename != QStringLiteral("intern")) {
        // Not fatal -- accept any entry name but warn
    }

    qsizetype dataStart = fnStart + fnLen + extraLen;
    if (dataStart + static_cast<qsizetype>(csize) > fileData.size()) {
        err = KpImporter::tr("ZIP compressed data extends beyond file end "
                             "(offset 0x%1, size %2, file %3)")
                  .arg(dataStart, 0, 16)
                  .arg(csize)
                  .arg(fileData.size());
        return false;
    }

    compressed = fileData.mid(static_cast<int>(dataStart),
                               static_cast<int>(csize));
    return true;
}

// ── Top-level importer ─────────────────────────────────────────────────────

KpImportResult KpImporter::importFromBytes(const QByteArray &fileData,
                                            uint32_t baseAddress)
{
    KpImportResult result;

    // 1. Validate the OLS file header (24 bytes)
    if (fileData.size() < 24) {
        result.error = KpImporter::tr("File too small for KP header (%1 bytes)")
                           .arg(fileData.size());
        return result;
    }

    // Check magic: u32 length prefix == 11 followed by "WinOLS File\0"
    static const char magic[] = "WinOLS File";
    uint32_t magicLen = qFromLittleEndian<uint32_t>(
        reinterpret_cast<const uchar *>(fileData.constData()));
    if (magicLen != 11
        || std::memcmp(fileData.constData() + 4, magic, 11) != 0) {
        result.error = KpImporter::tr("Invalid OLS magic header");
        return result;
    }

    result.formatVersion = qFromLittleEndian<uint32_t>(
        reinterpret_cast<const uchar *>(fileData.constData() + 16));
    result.declaredFileSize = qFromLittleEndian<uint32_t>(
        reinterpret_cast<const uchar *>(fileData.constData() + 20));

    if (result.declaredFileSize != static_cast<uint32_t>(fileData.size())) {
        result.warnings.append(
            KpImporter::tr("Header declares file size %1 but actual is %2")
                .arg(result.declaredFileSize)
                .arg(fileData.size()));
    }

    // 2. Extract the "intern" entry from the embedded ZIP
    QByteArray compressed;
    uint32_t uncompressedSize = 0;
    uint16_t method = 0;
    QString extractErr;

    if (!extractInternEntry(fileData, compressed, uncompressedSize,
                            method, extractErr)) {
        result.error = extractErr;
        return result;
    }

    // 3. Decompress the intern payload
    QByteArray intern;
    if (method == 8) {
        // Deflate
        QString inflateErr;
        intern = ZipDecompressor::decompress(compressed,
                                             static_cast<qsizetype>(uncompressedSize),
                                             &inflateErr);
        if (intern.isEmpty()) {
            result.error = KpImporter::tr("Failed to inflate intern: %1")
                               .arg(inflateErr);
            return result;
        }
    } else if (method == 0) {
        // Stored (no compression)
        intern = compressed;
    } else {
        result.error = KpImporter::tr("Unsupported ZIP compression method %1")
                           .arg(method);
        return result;
    }

    if (static_cast<uint32_t>(intern.size()) != uncompressedSize) {
        result.warnings.append(
            KpImporter::tr("Decompressed size %1 != declared %2")
                .arg(intern.size())
                .arg(uncompressedSize));
    }

    // 4. Parse map records from the intern payload.
    //
    // KP intern records DO NOT use the OLS Kennfeld wire format — they use
    // a simpler comment-prefixed layout that the Python reference at
    // parse_kp.py documents:
    //
    //   byte[0]      : 0x00
    //   u32[1..5]    : map_count
    //   byte[5]      : 0x00
    //   u32[6..10]   : 0xFFFFFFFF
    //   u32[10..14]  : 0x00000000
    //
    //   Then `map_count` records, each:
    //     u32 comment_length (5..200; real comments are 16/53/56 in samples)
    //     bytes[length] comment text (Latin-1 / Win-1252)
    //     ~426 bytes metadata (sub-regions delimited by 0xFFFFFFFF;
    //                          axis sizes, IEEE-754 scaling doubles,
    //                          source addresses, trailing flags 01 01 01)
    //
    // Map names = comments. Address/dims best-effort from metadata.
    auto findMaps = [&result, baseAddress](const QByteArray &payload) {
        QVector<MapInfo> maps;
        if (payload.size() < 14) {
            result.warnings.append(KpImporter::tr(
                "intern payload too small (%1 bytes)").arg(payload.size()));
            return maps;
        }
        const auto *p = reinterpret_cast<const uchar *>(payload.constData());
        const uint32_t mapCount = qFromLittleEndian<uint32_t>(p + 1);
        if (mapCount == 0 || mapCount > 100000) {
            result.warnings.append(KpImporter::tr(
                "intern payload map count %1 out of range").arg(mapCount));
            return maps;
        }
        // Walk forward from offset 14 looking for record headers.
        QVector<int> mapStarts;
        int pos = 14;
        const int sz = payload.size();
        while (pos < sz - 4 && mapStarts.size() < int(mapCount)) {
            const uint32_t cl = qFromLittleEndian<uint32_t>(p + pos);
            if (cl >= 5 && cl < 200 && pos + 4 + int(cl) <= sz) {
                int printable = 0;
                bool hasSpace = false;
                for (uint32_t i = 0; i < cl; ++i) {
                    uint8_t b = p[pos + 4 + i];
                    if ((b >= 0x20 && b < 0x7F) || b >= 0xA0) ++printable;
                    if (b == ' ') hasSpace = true;
                }
                if (printable >= int(cl) - 1 && hasSpace) {
                    mapStarts.append(pos);
                    pos += 4 + int(cl);
                    continue;
                }
            }
            ++pos;
        }
        maps.reserve(mapStarts.size());
        for (int idx = 0; idx < mapStarts.size(); ++idx) {
            const int start = mapStarts[idx];
            const uint32_t cl = qFromLittleEndian<uint32_t>(p + start);
            QByteArray commentBytes = payload.mid(start + 4, int(cl));
            QString comment = QString::fromLatin1(commentBytes).trimmed();
            const int metaOff = start + 4 + int(cl);
            const int nextEnd = (idx + 1 < mapStarts.size())
                                  ? (mapStarts[idx + 1] - 5) : sz;
            const int metaLen = qMax(0, nextEnd - metaOff);

            MapInfo m;
            m.name           = comment;
            m.description    = comment;
            m.type           = QStringLiteral("MAP");
            m.dimensions.x   = 1;
            m.dimensions.y   = 1;
            m.dataSize       = 2;
            m.length         = m.dimensions.x * m.dimensions.y * m.dataSize;
            m.rawAddress     = baseAddress;
            m.address        = 0;
            m.linkConfidence = 60;   // medium — name confirmed, address heuristic

            // Best-effort dim extraction from the first 16 bytes of metadata.
            if (metaLen >= 16) {
                const auto *mp = reinterpret_cast<const uchar *>(
                    payload.constData() + metaOff);
                for (int off : {0, 4, 8, 12}) {
                    uint16_t a = qFromLittleEndian<uint16_t>(mp + off);
                    uint16_t b = qFromLittleEndian<uint16_t>(mp + off + 2);
                    if (a >= 1 && a <= 256 && b >= 1 && b <= 256
                        && (a > 1 || b > 1)) {
                        m.dimensions.x = a;
                        m.dimensions.y = b;
                        m.length = m.dimensions.x * m.dimensions.y * m.dataSize;
                        if (a == 1 || b == 1) m.type = QStringLiteral("CURVE");
                        break;
                    }
                }
            }
            maps.append(m);
        }
        if (maps.size() != int(mapCount)) {
            result.warnings.append(KpImporter::tr(
                "intern map_count = %1 but parser found %2 records")
                    .arg(mapCount).arg(maps.size()));
        }
        return maps;
    };

    result.maps = findMaps(intern);
    result.mapCount = static_cast<uint32_t>(result.maps.size());

    return result;
}

} // namespace ols
