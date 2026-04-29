/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QtEndian>
#include <cstdint>

namespace ols {

// The 7 known 4-byte LE magic anchors scanned in the preamble (first 1008 bytes).
// See OLS_LOAD_WRAPPER.md for descriptions.
namespace MagicValues {
    constexpr uint32_t M1 = 0x42007899;  // Version-record fence
    constexpr uint32_t M2 = 0x11883377;  // Version-array dispatch
    constexpr uint32_t M3 = 0x98728833;  // Per-Version directory
    constexpr uint32_t M4 = 0x08260064;  // Old-format path
    constexpr uint32_t M5 = 0xCD23018A;  // Project-properties extension
    constexpr uint32_t M6 = 0x88271283;  // Optional comment / build fingerprint
    constexpr uint32_t M7 = 0x84C0AD36;  // Optional XOR-scrambled trailer
}

/// File offsets of each magic anchor, or -1 if not found.
struct MagicAnchors {
    qint64 m1 = -1;
    qint64 m2 = -1;
    qint64 m3 = -1;
    qint64 m4 = -1;
    qint64 m5 = -1;
    qint64 m6 = -1;
    qint64 m7 = -1;
};

class OlsMagicScanner {
public:
    /// Scan the first `preambleLen` bytes of `fileData` for the 7 magic anchors.
    /// Returns a MagicAnchors struct with the file offset of each found anchor
    /// (pointing to the first byte of the 4-byte magic), or -1 if not found.
    static MagicAnchors scan(const QByteArray &fileData, int preambleLen = 1008);
};

} // namespace ols
