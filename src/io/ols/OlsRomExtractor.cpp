// Universal ROM extractor for WinOLS .ols files.
//
// Two-path implementation (mirror of extract_rom.py):
//
//   1. **Modern path** (fmtVer >= 200 OR file contains FADECAFE/CAFEAFFE
//      sentinels): walks every (FADECAFE, CAFEAFFE) sentinel pair, parses
//      the 8-u32 segment descriptor that precedes it, and extracts the
//      flash bytes per the descriptor's [fb, fe] range.  The 18-byte
//      "project context slot" preceding each descriptor can hold an ASCII
//      project tag (e.g. "1037505704" for Seat Leon, "1037503982C617S3OH"
//      for Porsche, "DDE731a___" for BMW F10) right-padded with 0xAF, OR
//      18 bytes of all-0xAF (no tag).  We do NOT hardcode any specific
//      project number — the tag is per-file customer metadata.
//
//   2. **Old-format path** (fmtVer < 200 OR sentinel search returned 0):
//      uses the IDA-derived per-Version directory header.  The 12 bytes
//      immediately before the M1 anchor (0x42007899) hold three u32 LE:
//        u32 numVersions_minus_1     (v333 in load wrapper)
//        u32 versionDataStart        (v340 — file offset of M3 anchor)
//        u32 versionRecordSize       (v367 — size of one Version payload)
//      The full ROM payload for Version i is exactly:
//        file[ versionDataStart + 4 + versionRecordSize * i ..
//              versionDataStart + 4 + versionRecordSize * (i+1) )
//      This is the same directory header WinOLS itself reads at line 1163
//      of sub_7FF72EE687D0; old-format files (EDC15/EDC16, fmtVer<200)
//      simply lack the FADECAFE descriptors that subdivide the slot in
//      modern files, so each Version's slot IS the ROM image.
//
// See SEGMENT_DESCRIPTOR_SCHEMA.md and OLS_ROM_EXTRACTION.md for the full
// wire layout and IDA-derived schema.

#include "OlsRomExtractor.h"
#include "OlsVersionDirectory.h"
#include <QtEndian>
#include <cstring>
#include <limits>

namespace ols {

// Universal sentinels (universal across modern WinOLS versions).
static constexpr uint32_t SENTINEL_A = 0xFADECAFE;   // at desc[5]
static constexpr uint32_t SENTINEL_B = 0xCAFEAFFE;   // at desc[6]

// 8-u32 descriptor begins 20 bytes BEFORE the FADECAFE u32.
static constexpr int DESC_PRE_OFFSET = 20;
// Project context slot is 18 bytes before desc[0].
static constexpr int PROJ_SLOT_LEN = 18;
// We only sanity-check the first 10 bytes of the slot (the "project tag").
static constexpr int PROJ_TAG_LEN = 10;
// data_start = proj_off - 26 (= desc_off - 44).  Per schema doc.
static constexpr int DATA_START_PRE_OFFSET = 26;
// Per SEGMENT_DESCRIPTOR_SCHEMA.md §Caveats: the first 76 bytes of each
// modern (FADECAFE-anchored) segment's data region are WinOLS framing —
// 1 index byte + 25 bytes of inline-payload header + 18 bytes of proj_slot
// + 32 bytes of descriptor = 76 bytes — and are NOT real ECU flash.
// assemble() strips these when building the flat ROM image so the
// extracted bytes equal the real flash content, not WinOLS metadata.
static constexpr uint32_t MODERN_FRAMING_BYTES = 76;
// Segment-size sanity bound (no real ECU flash slice exceeds 16 MB).
static constexpr uint32_t MAX_SEG_SIZE = 16u * 1024u * 1024u;
// fmtVer threshold below which we skip the modern path entirely.
static constexpr uint32_t MODERN_FMTVER_THRESHOLD = 200;

// Old-format directory sanity bounds.
static constexpr uint32_t OLD_FMT_MAX_VERSIONS = 64;
static constexpr uint32_t OLD_FMT_MAX_REC_SIZE = 64u * 1024u * 1024u;

// ── Inline LE reader ──────────────────────────────────────────────────────

static inline uint32_t peekU32(const QByteArray &buf, qsizetype off)
{
    return qFromLittleEndian<uint32_t>(
        reinterpret_cast<const uchar *>(buf.constData() + off));
}

static inline bool isPrintable(uint8_t b) { return b >= 0x20 && b < 0x7F; }

// Validate the 10-byte project tag slot.  Either all 0xAF (no tag) or
// all printable ASCII (tag like "1037505704", "DDE731a___" etc).  Mixed
// binary slots come from nested/secondary descriptors that we skip.
static bool isValidProjSlot(const QByteArray &buf, qsizetype projOff)
{
    if (projOff + PROJ_TAG_LEN > buf.size())
        return false;
    const auto *p = reinterpret_cast<const uint8_t *>(buf.constData() + projOff);
    bool allAf = true, allPrint = true;
    for (int i = 0; i < PROJ_TAG_LEN; ++i) {
        if (p[i] != 0xAF) allAf = false;
        if (!isPrintable(p[i])) allPrint = false;
    }
    return allAf || allPrint;
}

// Decode the optional ASCII tag (everything in slot[0..10) before 0xAF).
static QString decodeProjTag(const QByteArray &buf, qsizetype projOff)
{
    if (projOff + PROJ_TAG_LEN > buf.size())
        return {};
    const auto *p = reinterpret_cast<const uint8_t *>(buf.constData() + projOff);
    QByteArray clean;
    clean.reserve(PROJ_TAG_LEN);
    for (int i = 0; i < PROJ_TAG_LEN; ++i) {
        if (isPrintable(p[i]) && p[i] != 0xAF)
            clean.append(static_cast<char>(p[i]));
    }
    return QString::fromLatin1(clean);
}

// ── Parse one descriptor anchored on a FADECAFE u32 ───────────────────────

static bool parseDescriptorAt(const QByteArray &buf, qsizetype fadeOff,
                              OlsSegment &out)
{
    qsizetype descOff = fadeOff - DESC_PRE_OFFSET;
    if (descOff < PROJ_SLOT_LEN)
        return false;
    if (descOff + 32 > buf.size())
        return false;

    uint32_t d[8];
    for (int i = 0; i < 8; ++i)
        d[i] = peekU32(buf, descOff + i * 4);

    if (d[5] != SENTINEL_A || d[6] != SENTINEL_B)
        return false;

    uint32_t fb = d[3] & 0x7FFFFFFF;
    uint32_t fe = d[4] & 0x7FFFFFFF;
    if (fb >= fe)
        return false;
    uint32_t sz = fe - fb + 1;
    if (sz > MAX_SEG_SIZE)
        return false;

    qsizetype projOff = descOff - PROJ_SLOT_LEN;
    if (!isValidProjSlot(buf, projOff))
        return false;

    out.projOffset = projOff;
    out.dataStart  = projOff - DATA_START_PRE_OFFSET;
    out.flashBase  = fb;
    out.flashSize  = sz;
    out.hash       = d[1];
    // Modern (FADECAFE-anchored) segments carry a 76-byte framing prefix
    // before the real ECU flash payload.  The old-format path sets this
    // to 0 (no framing — the whole payload is real flash).
    out.framingBytes = (sz > MODERN_FRAMING_BYTES) ? MODERN_FRAMING_BYTES : 0;
    // segmentIndex set by caller
    return true;
}

// ── Find all primary segments (modern path) ───────────────────────────────

static QVector<OlsSegment> findAllSegments(const QByteArray &buf)
{
    QVector<OlsSegment> segs;
    static const QByteArray fadeLE = QByteArray::fromHex("FECADEFA");
    static const QByteArray cafeLE = QByteArray::fromHex("FEAFFECA");

    qsizetype pos = 0;
    while (true) {
        qsizetype j = buf.indexOf(fadeLE, pos);
        if (j < 0)
            break;
        // Cheap pre-check: CAFEAFFE u32 must immediately follow FADECAFE.
        if (j + 8 <= buf.size()
            && std::memcmp(buf.constData() + j + 4, cafeLE.constData(), 4) == 0) {
            OlsSegment sd;
            if (parseDescriptorAt(buf, j, sd))
                segs.append(sd);
        }
        pos = j + 1;
    }
    return segs;
}

// ── Mark PRIMARY vs secondary segments + capture inter-segment preambles ──
//
// A FADECAFE-anchored segment is a "primary" when its data_start does NOT
// lie inside the previous primary's [dataStart, dataStart+flashSize) range.
// Secondary (nested) FADECAFE descriptors live inside a primary's payload
// region — e.g. Seat Leon MED17 has 16 primaries + 10 secondaries = 26
// sentinel pairs.  Preambles (DEADBEEF separator + optional inter-segment
// padding) are captured from the previous PRIMARY's end up to the current
// primary's dataStart.  Secondaries get empty preambles (they're not emitted
// independently on export).
static void classifyPrimariesAndCapturePreambles(QVector<OlsSegment> &segs,
                                                 const QByteArray &buf)
{
    uint32_t prevPrimaryEnd = 0;
    qsizetype prevPrimaryEndFile = 0;
    bool havePrev = false;
    for (auto &s : segs) {
        const uint32_t ds = static_cast<uint32_t>(s.dataStart);
        const bool primary = !havePrev || ds >= prevPrimaryEnd;
        s.isPrimary = primary;
        if (primary) {
            if (havePrev) {
                const qsizetype gapStart = prevPrimaryEndFile;
                const qsizetype gapEnd   = s.dataStart;
                if (gapEnd > gapStart && gapStart >= 0 && gapEnd <= buf.size())
                    s.preamble = buf.mid(gapStart, gapEnd - gapStart);
            }
            prevPrimaryEnd = ds + s.flashSize;
            prevPrimaryEndFile = s.dataStart + s.flashSize;
            havePrev = true;
        }
    }
}

// ── Group into Versions ───────────────────────────────────────────────────
// A new Version begins each time flash_base resets to a smaller value.

static QVector<OlsRomResult> groupByVersion(const QVector<OlsSegment> &segs)
{
    QVector<OlsRomResult> versions;
    QVector<OlsSegment> cur;
    int prev = -1;

    for (const auto &s : segs) {
        if (static_cast<int>(s.flashBase) < prev) {
            OlsRomResult v;
            v.versionIndex = versions.size();
            v.segments = cur;
            versions.append(std::move(v));
            cur.clear();
        }
        cur.append(s);
        prev = static_cast<int>(s.flashBase);
    }
    if (!cur.isEmpty()) {
        OlsRomResult v;
        v.versionIndex = versions.size();
        v.segments = cur;
        versions.append(std::move(v));
    }
    return versions;
}

// ── Old-format path: IDA-derived per-Version directory reader ─────────────
//
// For pre-200 .ols files (no FADECAFE/CAFEAFFE sentinels), WinOLS uses
// the per-Version directory header anchored on M1 (0x42007899).  The 12
// bytes immediately before M1 hold three u32 LE that describe the
// payload region exactly the same way they do for modern files —
// modern files just additionally subdivide each Version slot via
// FADECAFE descriptors.  See OLS_ROM_EXTRACTION.md §4.
//
// Returns one OlsRomResult per Version with a single segment covering
// the full Version payload, or an empty vector if the directory header
// can't be located/validated.

static QVector<OlsRomResult> oldFormatVersionsFromDirectory(
    const QByteArray &fileData)
{
    QStringList warnings;
    auto dir = OlsVersionDirectory::parse(fileData, &warnings);
    if (dir.numVersions == 0) {
        return {};
    }

    // Sanity bounds — reject obviously corrupt directory headers so we
    // don't allocate gigabytes of zero bytes for a malformed file.
    if (dir.numVersions > OLD_FMT_MAX_VERSIONS) return {};
    if (dir.versionRecordSize == 0
        || dir.versionRecordSize > OLD_FMT_MAX_REC_SIZE) {
        return {};
    }

    const qsizetype expectedEnd =
        static_cast<qsizetype>(dir.versionDataStart) + 4
        + static_cast<qsizetype>(dir.versionRecordSize) * dir.numVersions;
    if (expectedEnd > fileData.size()) {
        return {};
    }

    QVector<OlsRomResult> versions;
    versions.reserve(static_cast<int>(dir.numVersions));
    for (uint32_t i = 0; i < dir.numVersions; ++i) {
        const qsizetype payloadOff =
            static_cast<qsizetype>(dir.versionDataStart) + 4
            + static_cast<qsizetype>(dir.versionRecordSize) * i;
        if (payloadOff + dir.versionRecordSize > fileData.size())
            break;

        OlsSegment seg;
        seg.segmentIndex = 0;
        seg.projOffset   = payloadOff;
        seg.dataStart    = payloadOff;
        // No real ECU flash address available pre-200 — the descriptor
        // fields that hold it (high-bit-set fb/fe) didn't exist yet.
        // Use the payload offset as a synthetic flash_base so the
        // identity translation flash_addr == file_off holds (matches
        // how old-format map records store ROM addresses as raw file
        // offsets, validated end-to-end on the Golf 5 EDC16CP3 sample).
        seg.flashBase    = static_cast<uint32_t>(payloadOff);
        seg.flashSize    = dir.versionRecordSize;
        seg.hash         = 0;

        OlsRomResult v;
        v.versionIndex = static_cast<int>(i);
        v.segments.append(seg);
        // Forward any non-fatal warnings collected by the directory
        // parser (e.g. file-size mismatch on appended-data cases).
        v.warnings = warnings;
        versions.append(std::move(v));
    }
    return versions;
}

// ── Public API ────────────────────────────────────────────────────────────

QVector<OlsRomResult> OlsRomExtractor::extractAll(const QByteArray &fileData)
{
    // Read fmtVer from header @0x10 (24-byte header is mandatory).
    uint32_t fmtVer = 0;
    if (fileData.size() >= 0x14)
        fmtVer = peekU32(fileData, 0x10);

    QVector<OlsSegment> rawSegs;

    // Modern path: try sentinel search if fmtVer is in modern range.
    if (fmtVer >= MODERN_FMTVER_THRESHOLD) {
        rawSegs = findAllSegments(fileData);
        classifyPrimariesAndCapturePreambles(rawSegs, fileData);
    }

    QVector<OlsRomResult> versions;

    if (!rawSegs.isEmpty()) {
        versions = groupByVersion(rawSegs);
        // When a new Version begins (flash_base resets) the first segment
        // of that Version inherited a preamble from the previous Version's
        // tail — clear it so the exporter treats it as a fresh slot start.
        for (auto &v : versions) {
            if (!v.segments.isEmpty())
                v.segments.first().preamble.clear();
        }
    } else {
        // Old-format files OR modern files where the sentinel search
        // turned up nothing → IDA-derived per-Version directory reader.
        versions = oldFormatVersionsFromDirectory(fileData);
        if (versions.isEmpty()) {
            OlsRomResult empty;
            empty.error = OlsRomExtractor::tr(
                "No ROM segments found (no FADECAFE sentinels and no "
                "valid M1-anchored per-Version directory header)");
            return { empty };
        }
    }

    // Number segments within each Version and slice the data bytes out.
    for (auto &ver : versions) {
        for (int i = 0; i < ver.segments.size(); ++i) {
            auto &seg = ver.segments[i];
            seg.segmentIndex = i;
            if (seg.dataStart >= 0
                && seg.dataStart + static_cast<qsizetype>(seg.flashSize) <= fileData.size()) {
                seg.data = fileData.mid(seg.dataStart, seg.flashSize);
            } else {
                ver.warnings.append(
                    OlsRomExtractor::tr("Segment %1: data_start 0x%2 + flash_size 0x%3 "
                                        "exceeds file bounds (%4)")
                        .arg(i)
                        .arg(seg.dataStart, 0, 16)
                        .arg(seg.flashSize, 0, 16)
                        .arg(fileData.size()));
            }
        }
        ver.assembledRom = assemble(ver.segments);
    }

    return versions;
}

qsizetype OlsRomExtractor::flashToFileOffset(const QVector<OlsSegment> &segments,
                                              uint32_t flashAddr)
{
    for (const auto &seg : segments) {
        if (seg.flashBase <= flashAddr
            && flashAddr < seg.flashBase + seg.flashSize) {
            return seg.dataStart + (flashAddr - seg.flashBase);
        }
    }
    return -1;
}

QByteArray OlsRomExtractor::assemble(const QVector<OlsSegment> &segments)
{
    if (segments.isEmpty()) return {};

    // Build a FLAT ROM image where byte at offset N corresponds to
    // effective flash address N.  For modern (FADECAFE-anchored) segments
    // we strip the 76-byte WinOLS framing prefix so the ROM byte stream
    // reflects real ECU flash content.  The "effective" flash range of a
    // segment is therefore [flashBase + framingBytes, flashBase + flashSize).
    //
    // Old-format segments have framingBytes=0 and behave exactly as before.
    //
    // The image spans [minEffBase, maxEffEnd) filled with 0xFF for gaps
    // between segments.
    uint32_t minBase = std::numeric_limits<uint32_t>::max();
    uint32_t maxEnd  = 0;
    for (const auto &s : segments) {
        if (s.flashSize <= s.framingBytes) continue;
        const uint32_t effBase = s.flashBase + s.framingBytes;
        const uint32_t effEnd  = s.flashBase + s.flashSize;
        if (effBase < minBase) minBase = effBase;
        if (effEnd  > maxEnd)  maxEnd  = effEnd;
    }

    if (maxEnd <= minBase) return {};

    QByteArray rom(static_cast<int>(maxEnd - minBase), '\xFF');
    for (const auto &s : segments) {
        if (s.flashSize <= s.framingBytes) continue;
        const uint32_t effBase = s.flashBase + s.framingBytes;
        const uint32_t effSize = s.flashSize - s.framingBytes;
        const uint32_t offset  = effBase - minBase;
        const qsizetype srcLen = s.data.size() > static_cast<qsizetype>(s.framingBytes)
            ? s.data.size() - static_cast<qsizetype>(s.framingBytes) : 0;
        const int copyLen = static_cast<int>(qMin(srcLen,
                                                  static_cast<qsizetype>(effSize)));
        if (copyLen > 0
            && offset + static_cast<uint32_t>(copyLen) <= static_cast<uint32_t>(rom.size())) {
            std::memcpy(rom.data() + offset,
                        s.data.constData() + s.framingBytes,
                        copyLen);
        }
    }

    return rom;
}

} // namespace ols
