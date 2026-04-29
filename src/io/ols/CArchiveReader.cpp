/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "CArchiveReader.h"
#include <QStringDecoder>
#include <stdexcept>

namespace ols {

// ── Helpers ─────────────────────────────────────────────────────────────────

void CArchiveReader::ensureAvailable(qsizetype n) const
{
    if (m_off + n > m_buf.size()) {
        throw std::runtime_error(
            QStringLiteral("CArchiveReader: read of %1 bytes at offset 0x%2 "
                           "exceeds buffer size 0x%3")
                .arg(n)
                .arg(m_off, 0, 16)
                .arg(m_buf.size(), 0, 16)
                .toStdString());
    }
}

// ── 1-byte primitives ───────────────────────────────────────────────────────

uint8_t CArchiveReader::u8()
{
    ensureAvailable(1);
    uint8_t v = static_cast<uint8_t>(m_buf[m_off]);
    m_off += 1;
    return v;
}

bool CArchiveReader::boolean()
{
    return u8() != 0;
}

// ── 4-byte primitives ───────────────────────────────────────────────────────

uint32_t CArchiveReader::u32()
{
    ensureAvailable(4);
    uint32_t v = qFromLittleEndian<uint32_t>(
        reinterpret_cast<const uchar *>(m_buf.constData() + m_off));
    m_off += 4;
    return v;
}

int32_t CArchiveReader::i32()
{
    ensureAvailable(4);
    int32_t v = qFromLittleEndian<int32_t>(
        reinterpret_cast<const uchar *>(m_buf.constData() + m_off));
    m_off += 4;
    return v;
}

// ── 8-byte primitives ───────────────────────────────────────────────────────

uint64_t CArchiveReader::u64()
{
    ensureAvailable(8);
    uint64_t v = qFromLittleEndian<uint64_t>(
        reinterpret_cast<const uchar *>(m_buf.constData() + m_off));
    m_off += 8;
    return v;
}

double CArchiveReader::f64()
{
    ensureAvailable(8);
    uint64_t bits = qFromLittleEndian<uint64_t>(
        reinterpret_cast<const uchar *>(m_buf.constData() + m_off));
    m_off += 8;
    double v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

// ── CString ─────────────────────────────────────────────────────────────────
// Wire format depends on format_version (see parse_ols.py line ~95 and
// FORMAT_VERSION_MATRIX.md):
//
//   schema <  439  : [u32 length][length bytes][u8 NUL]          (length > 0)
//                    [u32 0]                                      (length == 0)
//
//   schema >= 439  : [i32 length][length bytes]  (no trailing NUL)
//                    length == -1 -> interned "-"
//                    length == -2 -> interned "?"
//                    length == -3 -> interned "%"
//                    length <= 0  -> empty string

QByteArray CArchiveReader::cstringBytes()
{
    // Read signed length so the 439+ sentinels (-1/-2/-3) are detectable.
    ensureAvailable(4);
    int32_t length = qFromLittleEndian<int32_t>(
        reinterpret_cast<const uchar *>(m_buf.constData() + m_off));
    m_off += 4;

    if (m_formatVersion >= 439) {
        // Modern format: no trailing NUL; negative lengths are interned tokens.
        if (length == -1) return QByteArrayLiteral("-");
        if (length == -2) return QByteArrayLiteral("?");
        if (length == -3) return QByteArrayLiteral("%");
        if (length <= 0)  return QByteArray();
        ensureAvailable(static_cast<qsizetype>(length));
        QByteArray body(m_buf.constData() + m_off, static_cast<qsizetype>(length));
        m_off += static_cast<qsizetype>(length);
        return body;
    }

    // Classic (schema < 439): length + body + NUL terminator.
    if (length <= 0)
        return QByteArray();

    ensureAvailable(static_cast<qsizetype>(length) + 1); // bytes + NUL

    QByteArray body(m_buf.constData() + m_off, static_cast<qsizetype>(length));
    m_off += static_cast<qsizetype>(length);

    // Consume and verify the trailing NUL
    uint8_t nul = static_cast<uint8_t>(m_buf[m_off]);
    m_off += 1;
    if (nul != 0x00) {
        throw std::runtime_error(
            QStringLiteral("CString NUL terminator mismatch at 0x%1: got 0x%2")
                .arg(m_off - 1, 0, 16)
                .arg(nul, 2, 16, QLatin1Char('0'))
                .toStdString());
    }

    return body;
}

/// Decode a raw byte string from an OLS file. Newer OLS versions
/// sometimes write UTF-8 (especially for user-entered comments and
/// project names); older versions use Windows-1252 (a superset of
/// Latin-1 that defines printable characters in the 0x80-0x9F range).
///
/// Strategy: try UTF-8 first. If it decodes cleanly (no replacement
/// characters, no lone surrogates) AND the result differs from a naive
/// Latin-1 decode, prefer UTF-8. Otherwise fall back to Windows-1252
/// via QStringDecoder so characters like "–" (0x96) render correctly.
static QString decodeOlsString(const QByteArray &raw)
{
    if (raw.isEmpty()) return QString();

    // Fast path: pure ASCII (all bytes < 0x80) — identical in all encodings.
    bool allAscii = true;
    for (char c : raw) {
        if (static_cast<uint8_t>(c) >= 0x80) { allAscii = false; break; }
    }
    if (allAscii)
        return QString::fromLatin1(raw);

    // Try UTF-8 first.
    QStringDecoder utf8(QStringDecoder::Utf8);
    QString asUtf8 = utf8(raw);
    if (!utf8.hasError() && !asUtf8.contains(QChar::ReplacementCharacter))
        return asUtf8;

    // Fall back to Windows-1252.
    QStringDecoder cp1252("Windows-1252");
    if (cp1252.isValid())
        return cp1252(raw);

    // Last resort: Latin-1 (identical to cp1252 for 0xA0-0xFF, missing
    // the 0x80-0x9F printable chars).
    return QString::fromLatin1(raw);
}

QString CArchiveReader::cstring()
{
    QByteArray raw = cstringBytes();
    return decodeOlsString(raw);
}

// ── byteArray ───────────────────────────────────────────────────────────────
// u32 length + length raw bytes (no NUL terminator).

QByteArray CArchiveReader::byteArray()
{
    uint32_t length = u32();
    if (length == 0)
        return QByteArray();
    if (length > 0x06400000u) {
        throw std::runtime_error(
            QStringLiteral("byteArray length 0x%1 out of range at 0x%2")
                .arg(length, 0, 16)
                .arg(m_off - 4, 0, 16)
                .toStdString());
    }
    ensureAvailable(static_cast<qsizetype>(length));
    QByteArray out(m_buf.constData() + m_off, static_cast<qsizetype>(length));
    m_off += static_cast<qsizetype>(length);
    return out;
}

// ── u64Array ────────────────────────────────────────────────────────────────
// u32 count + count * 8 bytes (each a u64 LE).

QVector<uint64_t> CArchiveReader::u64Array()
{
    uint32_t count = u32();
    if (count > 0x00100000u) {
        throw std::runtime_error(
            QStringLiteral("u64Array count 0x%1 out of range at 0x%2")
                .arg(count, 0, 16)
                .arg(m_off - 4, 0, 16)
                .toStdString());
    }
    QVector<uint64_t> result;
    result.reserve(static_cast<int>(count));
    for (uint32_t i = 0; i < count; ++i)
        result.append(u64());
    return result;
}

// ── bulk ────────────────────────────────────────────────────────────────────

QByteArray CArchiveReader::bulk(qsizetype n)
{
    ensureAvailable(n);
    QByteArray out(m_buf.constData() + m_off, n);
    m_off += n;
    return out;
}

// ── verifyMagic ─────────────────────────────────────────────────────────────

bool CArchiveReader::verifyMagic(uint32_t expected, bool strict)
{
    uint32_t got = u32();
    if (got == expected)
        return true;
    if (strict) {
        throw std::runtime_error(
            QStringLiteral("magic mismatch at 0x%1: got 0x%2, expected 0x%3")
                .arg(m_off - 4, 0, 16)
                .arg(got, 8, 16, QLatin1Char('0'))
                .arg(expected, 8, 16, QLatin1Char('0'))
                .toStdString());
    }
    return false;
}

// ── errorContext ────────────────────────────────────────────────────────────

QString CArchiveReader::errorContext() const
{
    return QStringLiteral("@0x%1").arg(m_off, 0, 16);
}

} // namespace ols
