#pragma once

#include <QByteArray>
#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QVector>
#include <cstdint>

namespace ols {

/// One ROM segment.
///
/// Modern path (fmtVer >= 200): discovered via the universal
/// FADECAFE/CAFEAFFE sentinel pair + 8-u32 descriptor pattern.  See
/// SEGMENT_DESCRIPTOR_SCHEMA.md.
///
/// Old-format path (fmtVer < 200 or no sentinels): produced by the
/// IDA-derived per-Version directory reader anchored on M1 (0x42007899);
/// the 12 bytes before M1 hold (numVersions-1, versionDataStart,
/// versionRecordSize) and each Version's full payload becomes one
/// segment.  flashBase is set to the payload's file offset because the
/// pre-200 directory does not embed real ECU flash addresses.
struct OlsSegment {
    int       segmentIndex = 0;
    qsizetype projOffset   = 0;   // file offset of the project-marker string
    qsizetype dataStart    = 0;   // file offset of flash data (= projOffset - 26)
    uint32_t  flashBase    = 0;   // absolute flash address of segment start
    uint32_t  flashSize    = 0;   // number of flash bytes in this segment
    uint32_t  hash         = 0;   // per-segment content hash from descriptor
    // Number of leading bytes in `data` that are WinOLS descriptor framing
    // (index byte + inline-payload header + proj_slot + 8-u32 descriptor =
    // 76 bytes) rather than real ECU flash content.  For the modern
    // FADECAFE path this is 76; for the old-format/legacy path it is 0.
    // assemble() and baseAddr computations skip these bytes.
    uint32_t  framingBytes = 0;
    QByteArray data;              // raw flash bytes (length == flashSize)
    // Bytes in the file immediately BEFORE `dataStart` that belong to this
    // segment in the Version-slot stream but are not part of the segment's
    // own framing (i.e. the DEADBEEF separator from the previous segment
    // plus any WinOLS-inserted padding).  Empty for the first PRIMARY
    // segment of a Version.  Captured verbatim so OlsExporter can reproduce
    // WinOLS's multi-segment on-disk layout byte-for-byte.  See
    // OlsImporter::importFromBytes where this is populated.
    QByteArray preamble;
    // True if this segment is the PRIMARY FADECAFE-anchored segment of a
    // region (i.e. its data_start does NOT lie inside a previous primary's
    // payload range).  Secondary/nested FADECAFE descriptors inside a
    // primary's payload area are flagged false.  OlsProjectBuilder uses
    // this to filter the export snapshot to primaries only; secondaries
    // are carried along automatically inside the primary's `data`.
    bool      isPrimary = true;
};

/// One Version (Original / Modified) within the .ols file.
struct OlsRomResult {
    int                 versionIndex = -1;
    QVector<OlsSegment> segments;
    QByteArray          assembledRom;  // all segments concatenated
    QString             error;
    QStringList         warnings;
};

/// Universal ROM segment extractor.
///
/// Two-path implementation (mirror of extract_rom.py):
///
///   1. Modern path (fmtVer >= 200): scans for the universal FADECAFE /
///      CAFEAFFE sentinel pair, parses the 8-u32 descriptor immediately
///      preceding each pair, validates the project context slot, and
///      groups segments into Versions.  Project-number tags are extracted
///      as informational metadata only — they vary per file (Seat Leon
///      "1037505704", Porsche "1037503982C617S3OH", BMW F10 "DDE731a___",
///      BMW M5 no-tag) and are NEVER hardcoded as search anchors.
///
///   2. Old-format path (fmtVer < 200 or no sentinels found): reads the
///      M1-anchored per-Version directory header (12 bytes before
///      0x42007899 hold numVersions-1, versionDataStart, versionRecordSize)
///      and emits one segment per Version covering its full payload.
///      Used for pre-200 .ols files (EDC15/EDC16 etc., fmtVer 100/114/116).
///
/// Port of extract_rom.py (Python reference implementation).
class OlsRomExtractor {
    Q_DECLARE_TR_FUNCTIONS(ols::OlsRomExtractor)
public:
    /// Discover all ROM segments in the file, grouped by Version.
    /// @param fileData  entire .ols file buffer
    /// @return  one OlsRomResult per Version (typically 2: Original + Modified)
    static QVector<OlsRomResult> extractAll(const QByteArray &fileData);

    /// Resolve a flash address to a file offset using a Version's segment table.
    /// @return  -1 if the address is not covered by any segment.
    static qsizetype flashToFileOffset(const QVector<OlsSegment> &segments,
                                       uint32_t flashAddr);

    /// Convenience: assemble all segments into a single contiguous ROM
    /// by concatenation (segment 0 first, then 1, etc.).
    static QByteArray assemble(const QVector<OlsSegment> &segments);
};

} // namespace ols
