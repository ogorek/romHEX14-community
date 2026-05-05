/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// uiwidgets.h — App-wide design system.
//
// Two namespaces:
//   Theme — color tokens, type tokens, radii, spacing, and stylesheet snippets
//   UI    — builder helpers for cards, header strips, primary/secondary buttons,
//           pills, form fields, section headers
//
// Every dialog should source its colors / paddings / radii from here so the
// whole app is restyled by editing one file. Inline stylesheets in dialogs are
// strongly discouraged.
// ─────────────────────────────────────────────────────────────────────────────

#include <QString>
#include <QFont>
#include <QDialog>
#include <QVector>

class QCheckBox;
class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QStandardItemModel;
class QTableView;
class QVBoxLayout;
class QWidget;

#include "appconfig.h"

namespace Theme {

// ── Runtime theme colors (read from AppConfig) ─────────────────────────────
// These are functions so they return current theme values, not compile-time.
#define _TC(field) (AppConfig::instance().colors.field.name())

inline QString bgRoot()       { return _TC(uiBg); }
inline QString bgCard()       { return _TC(uiPanel); }
inline QString bgSunken()     { return _TC(uiBg); }
inline QString bgHover()      { return _TC(buttonBg); }
inline QString border()       { return _TC(uiBorder); }
inline QString borderSubtle() { return _TC(buttonBg); }
inline QString borderHover()  { return _TC(uiAccent).isEmpty() ? "#58a6ff" : _TC(uiAccent); }

inline QString textPrimary()  { return _TC(uiText); }
inline QString textBright()   { return _TC(uiText); }
inline QString textMuted()    { return _TC(uiTextDim); }
inline QString textDim()      { return _TC(uiTextDim); }
inline constexpr const char *textOnPrimary  = "#ffffff";

inline QString primary()      { return _TC(uiAccent); }
inline QString primaryHover() { return AppConfig::instance().colors.uiAccent.lighter(120).name(); }
inline QString primaryPressed(){ return AppConfig::instance().colors.uiAccent.darker(130).name(); }
inline QString accent()       { return AppConfig::instance().colors.uiAccent.lighter(140).name(); }
inline QString accentDim()    { return AppConfig::instance().colors.uiAccent.lighter(160).name(); }

inline constexpr const char *success        = "#3fb950";
inline constexpr const char *successButton  = "#238636";

inline constexpr const char *danger         = "#f85149";
inline constexpr const char *dangerButton   = "#da3633";

#undef _TC

inline constexpr const char *warning        = "#f0883e";
inline constexpr const char *info           = "#79c0ff";

// ── Type scale (point sizes) ────────────────────────────────────────────────
inline constexpr int captionPt = 8;    // muted small labels, status bar
inline constexpr int bodyPt    = 9;    // default body
inline constexpr int headerPt  = 11;   // section headers / strong body
inline constexpr int titlePt   = 14;   // dialog titles, panel headlines
inline constexpr int displayPt = 18;   // hero numbers / wordmarks

// ── Radii ───────────────────────────────────────────────────────────────────
inline constexpr int radiusButton = 6;
inline constexpr int radiusCard   = 8;
inline constexpr int radiusPill   = 999;
inline constexpr int radiusInput  = 4;

// ── Spacing tokens ──────────────────────────────────────────────────────────
inline constexpr int spaceXS = 4;
inline constexpr int spaceS  = 8;
inline constexpr int spaceM  = 12;
inline constexpr int spaceL  = 16;
inline constexpr int spaceXL = 24;
inline constexpr int spaceXXL = 32;

// ── Stylesheet snippets ─────────────────────────────────────────────────────
//
// Pattern: assign these via `widget->setObjectName("primary")` etc. and let the
// global stylesheet do the rest. Or call the matching helper in `UI::` to get
// a styled widget directly.

// Returns the global QSS that the app installs at startup. Includes object-name
// based rules for #primary / #destructive / #flat buttons, [role="card"] frames,
// .pill labels, etc. Append to the existing style.qss content.
QString objectStyles();

QString primaryButtonQss();
QString destructiveButtonQss();
QString flatButtonQss();
QString cardFrameQss();
QString sunkenInputQss();
QString pillQss(const QString &kind);   // "success" | "warning" | "danger" | "info" | "neutral"

} // namespace Theme

namespace UI {

// ── Card / surface helpers ──────────────────────────────────────────────────
QFrame *makeCard(QWidget *parent = nullptr);

// Header strip used by About / HexCompare / etc.
//   [icon-tile] [title (large) + subtitle stack] [stretch] [optional pill]
// Pass empty pillText to omit the pill.
QFrame *makeHeaderStrip(const QString &iconGlyph,
                        const QString &title,
                        const QString &subtitle,
                        const QString &pillText = QString(),
                        QWidget *parent = nullptr);

// ── Buttons ─────────────────────────────────────────────────────────────────
QPushButton *makePrimaryButton(const QString &text, QWidget *parent = nullptr);
QPushButton *makeSecondaryButton(const QString &text, QWidget *parent = nullptr);   // default outline
QPushButton *makeDestructiveButton(const QString &text, QWidget *parent = nullptr);
QPushButton *makeFlatButton(const QString &text, QWidget *parent = nullptr);

// ── Labels ──────────────────────────────────────────────────────────────────
// Section header = small uppercase muted, used above feature grids etc.
QLabel *makeSectionHeader(const QString &text, QWidget *parent = nullptr);

// Pill = capsule label. kind: "success" | "warning" | "danger" | "info" | "neutral"
QLabel *makePill(const QString &text, const QString &kind, QWidget *parent = nullptr);

// ── Form helpers ────────────────────────────────────────────────────────────
// label-ABOVE-field layout: stacks `label / input / optional helper text`.
// Pass `required=true` to append a small red `*` to the label.
QWidget *makeFormField(const QString &label,
                       QWidget *input,
                       const QString &helper = QString(),
                       bool required = false,
                       QWidget *parent = nullptr);

// ── Fonts ───────────────────────────────────────────────────────────────────
// Returns a portable fixed-pitch font: uses QFontDatabase::systemFont so
// macOS gets Menlo, Linux gets DejaVu Sans Mono, Windows gets Consolas.
QFont fixedFont(int pt = Theme::bodyPt);

// Returns a QFont with the app's UI face at the given size / weight.
QFont uiFont(int pt = Theme::bodyPt, int weight = -1 /* QFont::Normal */);

// ── Universal destructive-change confirmation dialog ────────────────────────
// Modal confirm used by DTC edits, patch apply, map-pack apply and AI tuning.
// Shows: risk-colored header strip + headline, description card, optional diff
// table of changes, optional "snapshot before applying" checkbox, optional
// type-to-confirm gate, and Cancel / Apply footer.
class RiskyChangeConfirmDialog : public QDialog {
    Q_OBJECT
public:
    enum class Risk { Info, Caution, Danger };

    struct ChangeRow {
        QString label;        // e.g. "MAP_INJ_DUR cell [4,5]"
        QString oldValue;     // display-formatted
        QString newValue;
        QString delta;        // optional; empty if not meaningful
    };

    explicit RiskyChangeConfirmDialog(QWidget *parent = nullptr);

    void setHeadline(const QString &text);
    void setDescription(const QString &text);
    void setRisk(Risk risk);
    void setChanges(const QVector<ChangeRow> &changes);
    void setSnapshotOption(bool show, bool defaultChecked = true);
    bool snapshotChecked() const;
    void setActionText(const QString &text);
    void setRequireTypedConfirmation(const QString &phrase);

private:
    void rebuildPrimaryButton();
    void updateRiskVisuals();
    void updateApplyEnabled();

    Risk             m_risk = Risk::Caution;
    QString          m_actionText;
    QString          m_typedPhrase;

    QFrame          *m_headerStrip   = nullptr;
    QFrame          *m_riskEdge      = nullptr;
    QLabel          *m_headlineLabel = nullptr;
    QLabel          *m_riskPill      = nullptr;

    QFrame              *m_descCard   = nullptr;
    QLabel              *m_descLabel  = nullptr;

    QFrame              *m_changesCard = nullptr;
    QTableView          *m_changesView = nullptr;
    QStandardItemModel  *m_changesModel = nullptr;
    QLabel              *m_emptyChangesNote = nullptr;

    QFrame          *m_snapshotRow = nullptr;
    QCheckBox       *m_snapshotCheck = nullptr;

    QFrame          *m_typedRow   = nullptr;
    QLineEdit       *m_typedEdit  = nullptr;

    QPushButton     *m_cancelBtn  = nullptr;
    QPushButton     *m_applyBtn   = nullptr;
    QFrame          *m_footerRow  = nullptr;
    QVBoxLayout     *m_root       = nullptr;
};

} // namespace UI
