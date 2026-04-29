/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// Top-level OLS importer — uses schema-driven ROM extraction and
// schema-driven Kennfeld parsing.
//
// Pipeline:
//   1. OlsHeader::parse()            -- 24-byte header validation
//   2. OlsMagicScanner::scan()       -- locate M1..M7 anchors
//   3. OlsProjectMetadata::parse()   -- 32 project-metadata fields
//   4. OlsVersionDirectory::parse()  -- per-Version directory
//   5. OlsRomExtractor::extractAll() -- schema-driven ROM segments
//   6. OlsKennfeldParser::parseAll() -- schema-driven map records

#include "OlsImporter.h"
#include "CArchiveReader.h"
#include "OlsHeader.h"
#include "OlsMagicScanner.h"
#include "OlsProjectMetadata.h"
#include "OlsVersionDirectory.h"
#include "OlsRomExtractor.h"
#include "OlsKennfeldParser.h"

#include <QtEndian>
#include <cstring>

namespace ols {

OlsImportResult OlsImporter::importFromBytes(const QByteArray &fileData)
{
    OlsImportResult result;

    // ─── 1. Parse header ───────────────────────────────────────────────
    result.header = OlsHeader::parse(fileData);
    if (!result.header.valid) {
        result.error = result.header.error;
        return result;
    }

    uint32_t fmtVer = result.header.formatVersion;

    // Only the Middle/New envelope (fmtVer >= 200) has a real
    // declared_size u32 at 0x14.  For Old files the u32 at 0x14 is the
    // length prefix of the first metadata CString; comparing it to the
    // file size is a category error and would always warn.
    if (fmtVer >= 200
        && result.header.declaredFileSize != static_cast<uint32_t>(fileData.size())) {
        result.warnings.append(
            OlsImporter::tr("Header declares size %1 but actual is %2")
                .arg(result.header.declaredFileSize)
                .arg(fileData.size()));
    }

    int schema = static_cast<int>(fmtVer);

    // ─── 2. Scan for magic anchors ─────────────────────────────────────
    MagicAnchors anchors = OlsMagicScanner::scan(fileData, 1008);

    // ─── 3. Parse project metadata ─────────────────────────────────────
    // Envelope varies across bands (FORMAT_VERSION_MATRIX.md):
    //   - Old  (fmtVer < 200): no declared-size u32 at 0x14; metadata
    //     starts at 0x14 (the u32 there is already the first CString's
    //     length prefix).
    //   - Middle / New (fmtVer >= 200): declared-size u32 at 0x14;
    //     metadata starts at 0x18.
    qsizetype metadataStart = (fmtVer >= 200) ? 0x18 : 0x14;
    try {
        CArchiveReader reader(fileData, metadataStart, fmtVer);
        result.metadata = OlsProjectMetadata::parse(reader, &result.warnings);
    } catch (const std::exception &e) {
        result.warnings.append(
            OlsImporter::tr("Project metadata parse failed: %1")
                .arg(QString::fromStdString(e.what())));
    }

    // ─── 4. Parse Version directory ────────────────────────────────────
    OlsVersionDirectory versionDir = OlsVersionDirectory::parse(
        fileData, &result.warnings);

    // ─── 5. Universal ROM extraction ───────────────────────────────────
    // Two-path: (a) modern files (fmtVer >= 200) use the universal
    // FADECAFE/CAFEAFFE sentinel pair to anchor 8-u32 segment descriptors;
    // (b) old files (fmtVer < 200) fall back to an entropy heuristic.
    // The "1037505704" string seen in some files is per-file customer
    // metadata (project number) and is NEVER hardcoded as a search anchor.
    QVector<OlsRomResult> romVersions = OlsRomExtractor::extractAll(fileData);

    // ─── 6. Find map region + parse Kennfeld records ───────────────────
    auto [mapRegionStart, mapRegionEnd] =
        OlsKennfeldParser::findMapRegion(fileData, schema);

    QVector<MapInfo> maps = OlsKennfeldParser::parseAll(
        fileData, mapRegionStart, mapRegionEnd, schema, &result.warnings);

    // ─── 7. Build Version results ──────────────────────────────────────
    // The assembled ROM is a FLAT image where byte[N] = flash address N.
    // MapInfo::rawAddress is the flash address; MapInfo::address must be
    // the offset into the assembled ROM for the Project model.
    //
    // baseAddress = the minimum flashBase across all segments of version 0.
    // address     = rawAddress - baseAddress (= direct index into assembledRom)

    if (!romVersions.isEmpty() && !romVersions[0].error.isEmpty()
        && romVersions.size() == 1) {
        result.warnings.append(romVersions[0].error);
        OlsVersion ver;
        ver.name = OlsImporter::tr("Default");
        ver.maps = maps;
        result.versions.append(std::move(ver));
    } else {
        for (auto &rv : romVersions) {
            OlsVersion ver;
            ver.name = OlsImporter::tr("Version %1").arg(rv.versionIndex);
            ver.romData = rv.assembledRom;
            ver.segments = rv.segments;
            ver.byteOrder = ByteOrder::LittleEndian;

            // Compute baseAddress = minimum effective flashBase for this
            // version.  The effective base accounts for the 76-byte OLS
            // framing at the start of each modern (FADECAFE) segment —
            // assemble() strips those bytes, so the flat ROM at offset 0
            // corresponds to the first *real* ECU byte after the framing.
            uint32_t baseAddr = 0;
            if (!rv.segments.isEmpty()) {
                baseAddr = rv.segments[0].flashBase + rv.segments[0].framingBytes;
                for (const auto &seg : rv.segments) {
                    const uint32_t eff = seg.flashBase + seg.framingBytes;
                    if (eff < baseAddr)
                        baseAddr = eff;
                }
            }

            // Translate map addresses from flash → ROM offset
            QVector<MapInfo> translatedMaps = maps;
            for (auto &m : translatedMaps) {
                m.rawAddress = m.address;  // preserve the original flash address
                m.address = (m.rawAddress >= baseAddr)
                    ? m.rawAddress - baseAddr : m.rawAddress;
                // Translate axis ROM addresses too
                if (m.xAxis.hasPtsAddress && m.xAxis.ptsAddress >= baseAddr)
                    m.xAxis.ptsAddress -= baseAddr;
                if (m.yAxis.hasPtsAddress && m.yAxis.ptsAddress >= baseAddr)
                    m.yAxis.ptsAddress -= baseAddr;
            }
            // Populate axis fixedValues by reading breakpoints from the
            // assembled ROM.  Without this, axis labels in MapOverlay are
            // empty.
            //
            // ─── AXIS BYTE-LAYOUT RESOLUTION (IMPORTANT) ─────────────────
            // The byte layout (width, endianness, signedness) comes from
            // the axis record's u32_116 enum (= AxisInfo::ptsDataType) and
            // its flag3 bool (= AxisInfo::ptsSigned).  These mirror the
            // exact fields OLS itself reads inside its converter
            // ; cell_bits at axis offset +124 is a
            // DISPLAY-only formatter hint and does NOT determine ROM cell
            // width.
            //
            // See AXIS_CELLWIDTH_SCHEMA.md
            // for the full enum table and the
            // pseudocode this function mirrors.
            //
            // We DO NOT probe byte-monotonicity any more.  OLS itself
            // doesn't, and the heuristic produced wrong results on:
            //   - single-breakpoint axes (nothing to compare)
            //   - wrapping axes (350°, 10°, 30°)
            //   - big-endian u16 axes (Mazda Denso etc.)
            //   - u16 axes whose low bytes happened to be monotonic.
            //
            // Fallback chain when ptsDataType == 0 (A2L imports / non-
            // OLS sources): use ptsDataSize/ptsSigned as before.
            for (auto &m : translatedMaps) {
                auto readAxisBreakpoints = [&](AxisInfo &ax, int count) {
                    if (!ax.hasPtsAddress || ax.ptsAddress == 0
                        || ax.ptsAddress == 0xFFFFFFFF || count <= 0)
                        return;

                    // Effective cell width.  When ptsDataType is set we trust
                    // it (it's OLS's own enum); otherwise fall back to
                    // ptsDataSize.
                    int cellBytes = ax.ptsDataSize;
                    if (cellBytes <= 0)
                        cellBytes = (m.dataSize > 0) ? m.dataSize : 2;
                    if (cellBytes != 1 && cellBytes != 2 && cellBytes != 4
                        && cellBytes != 8)
                        cellBytes = 2;

                    int startOff = static_cast<int>(ax.ptsAddress);
                    if (startOff < 0
                        || startOff + count * cellBytes > ver.romData.size())
                        return;
                    const auto *rom = reinterpret_cast<const uint8_t *>(
                        ver.romData.constData());

                    // ── Mirror of the data_type switch in .
                    // dt = 0 path uses the cellBytes/ptsSigned fallback so
                    // A2L imports keep working.
                    const uint32_t dt = ax.ptsDataType;
                    const bool sgn = ax.ptsSigned;
                    auto decodeOne = [&](int off) -> double {
                        switch (dt) {
                        case 2: { // u16 BE
                            uint16_t v = (uint16_t(rom[off]) << 8) | rom[off + 1];
                            return sgn ? double(int16_t(v)) : double(v);
                        }
                        case 3: { // u16 LE
                            uint16_t v = uint16_t(rom[off])
                                       | (uint16_t(rom[off + 1]) << 8);
                            return sgn ? double(int16_t(v)) : double(v);
                        }
                        case 4: { // u32 BE
                            uint32_t v = (uint32_t(rom[off]) << 24)
                                       | (uint32_t(rom[off + 1]) << 16)
                                       | (uint32_t(rom[off + 2]) << 8)
                                       |  uint32_t(rom[off + 3]);
                            return sgn ? double(int32_t(v)) : double(v);
                        }
                        case 5: { // u32 LE
                            uint32_t v = uint32_t(rom[off])
                                       | (uint32_t(rom[off + 1]) << 8)
                                       | (uint32_t(rom[off + 2]) << 16)
                                       | (uint32_t(rom[off + 3]) << 24);
                            return sgn ? double(int32_t(v)) : double(v);
                        }
                        case 6: { // float BE
                            uint32_t v = (uint32_t(rom[off]) << 24)
                                       | (uint32_t(rom[off + 1]) << 16)
                                       | (uint32_t(rom[off + 2]) << 8)
                                       |  uint32_t(rom[off + 3]);
                            float f; std::memcpy(&f, &v, 4); return f;
                        }
                        case 7: { // float LE
                            float f; std::memcpy(&f, rom + off, 4); return f;
                        }
                        case 11: { // u64 LE
                            uint64_t v = 0;
                            std::memcpy(&v, rom + off, 8);
                            return double(v);
                        }
                        case 13: { // double LE
                            double f; std::memcpy(&f, rom + off, 8); return f;
                        }
                        case 1: case 8: case 9: { // u8
                            uint8_t v = rom[off];
                            return sgn ? double(int8_t(v)) : double(v);
                        }
                        default: {
                            // dt == 0 → fall back to cellBytes/sgn
                            switch (cellBytes) {
                            case 1: {
                                uint8_t v = rom[off];
                                return sgn ? double(int8_t(v)) : double(v);
                            }
                            case 2: {
                                uint16_t v = qFromLittleEndian<uint16_t>(rom + off);
                                return sgn ? double(int16_t(v)) : double(v);
                            }
                            case 4: {
                                uint32_t v = qFromLittleEndian<uint32_t>(rom + off);
                                return sgn ? double(int32_t(v)) : double(v);
                            }
                            default: {
                                uint8_t v = rom[off];
                                return sgn ? double(int8_t(v)) : double(v);
                            }
                            }
                        }
                        }
                    };

                    QVector<double> rawVals;
                    rawVals.reserve(count);
                    for (int i = 0; i < count; ++i)
                        rawVals.append(decodeOne(startOff + i * cellBytes));

                    ax.fixedValues = rawVals;
                    ax.ptsCount = count;
                    ax.ptsDataSize = cellBytes;
                };
                readAxisBreakpoints(m.xAxis, m.dimensions.x);
                readAxisBreakpoints(m.yAxis, m.dimensions.y);
            }

            ver.maps = translatedMaps;
            ver.baseAddress = baseAddr;

            for (const auto &w : rv.warnings)
                result.warnings.append(w);

            result.versions.append(std::move(ver));
        }
    }

    return result;
}

} // namespace ols
