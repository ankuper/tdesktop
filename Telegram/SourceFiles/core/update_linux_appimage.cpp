/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/update_linux_appimage.h"

#include "base/debug_log.h"
#include "lang/lang_keys.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QPointer>
#include <QtCore/QProcess>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QStandardPaths>
#include <QtCore/QStringList>
#include <QtCore/QtGlobal>

#include <QtCore/QDir>

#include <fcntl.h>
#include <unistd.h>

namespace Core::Linux {
namespace {

// Pinned release-key fingerprint — see docs/updates-linux.md §current-key.
// v0.1.0 dev release key, generated 2026-05-09 on .lnx (192.168.30.191).
// MUST stay in sync with docs/updates-linux.md and the bundled pubring.
constexpr auto kReleaseKeyFingerprint =
	"1DED8ADEF19BE7CAC93DEC5788161B1A989EF692";

// Appimage-self-update.sh lives next to this binary in the AppImage
// payload at usr/share/Telegram/scripts/appimage-self-update.sh, OR
// in the development tree under Telegram/build/. We probe both.
[[nodiscard]] QString FindHelperScript() {
	const auto appImagePath = qEnvironmentVariable("APPIMAGE");
	if (!appImagePath.isEmpty()) {
		// Inside an extracted AppImage, AppRun lives next to the
		// usr/ tree. Helper scripts are bundled at
		// usr/share/Telegram/scripts/.
		const auto extractDir = qEnvironmentVariable("APPDIR");
		if (!extractDir.isEmpty()) {
			const auto bundled = extractDir
				+ u"/usr/share/Telegram/scripts/appimage-self-update.sh"_q;
			if (QFile::exists(bundled)) {
				return bundled;
			}
		}
	}
	const auto candidates = QStringList{
		u"./Telegram/build/appimage-self-update.sh"_q,
		u"../Telegram/build/appimage-self-update.sh"_q,
	};
	for (const auto &c : candidates) {
		if (QFile::exists(c)) {
			return QFileInfo(c).absoluteFilePath();
		}
	}
	return QString();
}

} // namespace

bool RunningInsideAppImage() {
	return !qEnvironmentVariable("APPIMAGE").isEmpty();
}

AppImageChecker::AppImageChecker(bool testing) : Checker(testing) {
}

AppImageChecker::~AppImageChecker() {
	if (_process && _process->state() != QProcess::NotRunning) {
		_process->terminate();
		_process->waitForFinished(1000);
		if (_process->state() != QProcess::NotRunning) {
			_process->kill();
		}
	}
}

void AppImageChecker::start() {
	const auto helper = FindHelperScript();
	if (helper.isEmpty()) {
		LOG(("Update Error: appimage-self-update.sh not found"));
		fail();
		return;
	}

	auto *process = new QProcess(this);
	_process = process;
	process->setProcessChannelMode(QProcess::SeparateChannels);

	auto env = QProcessEnvironment::systemEnvironment();
	env.insert(u"RELEASE_KEY_FPR"_q, QString::fromLatin1(kReleaseKeyFingerprint));
	if (!env.contains(u"PUBLISH_BASE_URL"_q)) {
		env.insert(u"PUBLISH_BASE_URL"_q,
			u"https://github.com/ankuper/tdesktop/releases/download"_q);
	}
	process->setProcessEnvironment(env);

	QObject::connect(process, &QProcess::readyReadStandardOutput, this, [=] {
		while (process->canReadLine()) {
			const auto line = QString::fromUtf8(
				process->readLine()).trimmed();
			onSubprocessLine(line);
		}
	});

	QObject::connect(process, &QProcess::finished, this, [=](int exitCode, QProcess::ExitStatus) {
		// Drain remaining output.
		while (process->canReadLine()) {
			onSubprocessLine(QString::fromUtf8(process->readLine()).trimmed());
		}
		onSubprocessFinished(exitCode);
	});

	process->start(u"/bin/bash"_q, { helper });
}

void AppImageChecker::onSubprocessLine(const QString &line) {
	// Protocol — see Telegram/build/appimage-self-update.sh header.
	if (line.startsWith(u"VERSION: "_q)) {
		_newVersion = line.mid(9);
	} else if (line.startsWith(u"SIZE: "_q)) {
		_newSizeBytes = line.mid(6).toLongLong();
	} else if (line.startsWith(u"FINGERPRINT: "_q)) {
		const auto reported = line.mid(13);
		if (reported != QString::fromLatin1(kReleaseKeyFingerprint)) {
			// The script disagrees with the binary's pin. Treat as
			// a verify failure (NFR20 — generic).
			LOG(("Update Error: helper fingerprint disagrees with binary pin"));
			_failed = true;
		}
	} else if (line.startsWith(u"ERROR: "_q)) {
		LOG(("Update Error: %1").arg(line.mid(7)));
		_failed = true;
	} else if (line == u"STATE: failed"_q) {
		_failed = true;
	}
	// STATE: ready / done are observational; the gate is the exit code.
}

void AppImageChecker::onSubprocessFinished(int exitCode) {
	// Anti-pattern §12.14 — verify chain inside the script. Here we
	// gate on exitCode 0 alone; any non-zero is treated as failure
	// generically (NFR20 — no class differentiation surfaced to UI).
	if (_failed || exitCode != 0) {
		fail();
		return;
	}

	// Build cache dir path matching the shell script's CACHE_DIR:
	//   ${XDG_CACHE_HOME:-$HOME/.cache}/Telegram/update/
	// (D2: do not use QStandardPaths::CacheLocation which includes
	// applicationName() and diverges from the shell script path.)
	const auto xdgCacheHome = qEnvironmentVariable("XDG_CACHE_HOME");
	const auto cacheBase = xdgCacheHome.isEmpty()
		? (QDir::homePath() + u"/.cache"_q)
		: xdgCacheHome;
	_verifiedAppImagePath =
		cacheBase + u"/Telegram/update/Telegram-x86_64-v2.AppImage"_q;

	if (!QFile::exists(_verifiedAppImagePath)) {
		LOG(("Update Error: helper exit 0 but candidate not present at %1"
			).arg(_verifiedAppImagePath));
		fail();
		return;
	}

	// Atomic replacement: rename verified candidate over the running AppImage.
	// Anti-pattern §12.14: any failure aborts without partial state.
	const auto appImagePath = qEnvironmentVariable("APPIMAGE");
	if (appImagePath.isEmpty()) {
		LOG(("Update Error: APPIMAGE env unset; cannot determine replacement target"));
		QFile::remove(_verifiedAppImagePath);
		fail();
		return;
	}

	// Preserve + enforce world-executable permissions (P26: umask 077 in
	// helper leaves candidate at 0755; after rename, re-apply explicitly).
	const auto perms =
		QFileDevice::ReadOwner  | QFileDevice::WriteOwner | QFileDevice::ExeOwner  |
		QFileDevice::ReadGroup  | QFileDevice::ExeGroup   |
		QFileDevice::ReadOther  | QFileDevice::ExeOther;

	if (!QFile::rename(_verifiedAppImagePath, appImagePath)) {
		LOG(("Update Error: rename(%1 -> %2) failed"
			).arg(_verifiedAppImagePath, appImagePath));
		QFile::remove(_verifiedAppImagePath);
		fail();
		return;
	}
	QFile(appImagePath).setPermissions(perms);

	// fsync parent directory for rename durability.
	{
		const auto parentPath = QFileInfo(appImagePath).absolutePath();
		const int fd = ::open(
			parentPath.toLocal8Bit().constData(),
			O_RDONLY | O_DIRECTORY);
		if (fd >= 0) {
			::fsync(fd);
			::close(fd);
		}
	}

	LOG(("Update Info: AppImage atomically replaced: %1").arg(appImagePath));

	// Signal "already latest" to the Updater (fires _isLatest toast).
	// TODO(story-2-7-F1): replace done(nullptr) with a proper consent
	// dialog + _ready path via update_checker.cpp hook after 2-13 closes.
	// For v0.1.0: rename is done; user must restart manually to run the
	// new version. The _isLatest toast is a UX compromise — not a crash.
	done(nullptr);
}

} // namespace Core::Linux
