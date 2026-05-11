/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

// Story 2-7 / AC#3 — Linux AppImage update integration.
//
// Owner: Story 2-7 (Linux release).
// Spec: docs/updates-linux.md
//
// This module provides a Linux-platform Checker that consumes the
// existing Updater::startImplementation() contract. When the running
// binary is an AppImage (APPIMAGE env var set), the existing tdesktop
// updater (per AR-G1 — single-updater mandate) dispatches through
// AppImageChecker which delegates verify+download to the
// `Telegram/build/appimage-self-update.sh` shell.
//
// Integration with update_checker.cpp (the one-line patch — apply
// CAREFULLY against the working tree, which currently has unrelated
// dirty edits):
//
//     // in Updater::start(), after sendRequest is decided:
//     if (sendRequest) {
// +       #if defined(Q_OS_LINUX) && !defined(TDESKTOP_DISABLE_AUTOUPDATE)
// +       if (Linux::RunningInsideAppImage()) {
// +           startImplementation(
// +               &_httpImplementation,
// +               std::make_unique<Linux::AppImageChecker>(_testing));
// +           _checking.fire({});
// +           return;
// +       }
// +       #endif
//         startImplementation(
//             &_httpImplementation,
//             std::make_unique<HttpChecker>(_testing));
//         ...
//     }
//
// The AppImage path takes precedence over Http+Mtp checkers on Linux
// because the legacy updates.telegram.org channel does not serve
// Type3-aware AppImage builds (the v1 channel only). FR38 + AR-G1
// are honoured: this is the same Updater (same UI flow, same
// consent surface), only with an AppImage-aware Checker.

#include "core/update_checker.h"

class QProcess;
template <typename T> class QPointer;

namespace Core::Linux {

// Returns true iff the current process was launched from inside an
// AppImage (the AppImage runtime sets the APPIMAGE env var to the
// absolute path of the bundle).
[[nodiscard]] bool RunningInsideAppImage();

// Subprocess-driven Checker. Reads stdout protocol from
// appimage-self-update.sh and produces an AbstractDedicatedLoader
// equivalent (see update_linux_appimage.cpp for the loader stub —
// the verify+download work is done by the script; the Loader here
// just exposes the cache-dir path of the verified AppImage so the
// existing application-side replace step can pick it up).
class AppImageChecker : public ::Core::Checker {
public:
	explicit AppImageChecker(bool testing);
	~AppImageChecker() override;

	void start() override;

private:
	void onSubprocessLine(const QString &line);
	void onSubprocessFinished(int exitCode);

	QPointer<QProcess> _process;
	QString _newVersion;
	qint64 _newSizeBytes = 0;
	QString _verifiedAppImagePath;
	bool _failed = false;

};

} // namespace Core::Linux
