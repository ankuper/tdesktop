/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <optional>
#include <memory>

#include "base/timer.h"
#include "base/object_ptr.h"
#include "core/core_settings_proxy.h"
#include "mtproto/connection_abstract.h"
#include "mtproto/mtproto_proxy_data.h"

/* === TYPE3-PROXY BEGIN === */
namespace Tdesktop::Teleproto3 {
class IndicatorC1;
} // namespace Tdesktop::Teleproto3
/* === TYPE3-PROXY END === */

namespace Ui {
class Show;
class BoxContent;
class InputField;
class PortInput;
class PasswordInput;
class Checkbox;
template <typename Enum>
class RadioenumGroup;
template <typename Enum>
class Radioenum;
} // namespace Ui

namespace Main {
class Account;
} // namespace Main

namespace Window {
class SessionController;
} // namespace Window

class ProxiesBoxController {
public:
	using ProxyData = MTP::ProxyData;
	using Type = ProxyData::Type;

	explicit ProxiesBoxController(not_null<Main::Account*> account);

	static void ShowApplyConfirmation(
		Window::SessionController *controller,
		Type type,
		const QMap<QString, QString> &fields);

	static object_ptr<Ui::BoxContent> CreateOwningBox(
		not_null<Main::Account*> account,
		const QString &highlightId = QString());
	static void Show(
		not_null<Window::SessionController*> controller,
		const QString &highlightId = QString());
	object_ptr<Ui::BoxContent> create(const QString &highlightId = QString());

	enum class ItemState {
		Connecting,
		Online,
		Checking,
		Available,
		Unavailable
	};
	struct ItemView {
		int id = 0;
		QString type;
		QString host;
		uint32 port = 0;
		int ping = 0;
		bool selected = false;
		bool deleted = false;
		bool supportsShare = false;
		bool supportsCalls = false;
		ItemState state = ItemState::Checking;

	};

	void deleteItem(int id);
	void deleteItems();
	void restoreItem(int id);
	void shareItem(int id, bool qr);
	void shareItems();
	void applyItem(int id);
	object_ptr<Ui::BoxContent> editItemBox(int id);
	object_ptr<Ui::BoxContent> addNewItemBox();
	bool setProxySettings(ProxyData::Settings value);
	void setProxyForCalls(bool enabled);
	void setProxyRotationEnabled(bool enabled);
	void setProxyRotationTimeout(int value);
	void setTryIPv6(bool enabled);
	rpl::producer<ProxyData::Settings> proxySettingsValue() const;

	[[nodiscard]] bool contains(const ProxyData &proxy) const;
	void addNewItem(const ProxyData &proxy);

	/* === TYPE3-PROXY BEGIN === */
	// FR9 same-key match helpers (story 2-2; AC-2).
	// Returns the item id of the first Mtproto3 entry whose 16 raw key
	// octets match proxy, or std::nullopt if none found.
	[[nodiscard]] auto findByType3Key(const ProxyData &proxy) const
		-> std::optional<int>;
	// Mutates the entry with the given id to updated in place (FR9 update
	// path). No-op if the entry is already identical or not found.
	void replaceType3InPlace(int id, const ProxyData &updated);

	// Story 2.5 Subtask 7.2 — factory for the persistent chat-list C1 indicator.
	// Creates an IndicatorC1 widget owned by `parent` that tracks the currently
	// selected Mtproto3 proxy's connection state via the views() event stream.
	// Returns nullptr if the active proxy is not Mtproto3.
	// The main window (or status-bar widget) calls this once at session start.
	// Forward-citation: the caller site (main window / status bar) is wired by
	// story 2.6 / 2.10 — the factory API is established here (story 2.5 boundary).
	[[nodiscard]] std::unique_ptr<Tdesktop::Teleproto3::IndicatorC1>
		createActiveC1Indicator(QWidget *parent);
	/* === TYPE3-PROXY END === */

	rpl::producer<ItemView> views() const;

	rpl::producer<bool> listShareableChanges() const;

	~ProxiesBoxController();

private:
	using Checker = MTP::details::ConnectionPointer;
	struct Item {
		int id = 0;
		ProxyData data;
		bool deleted = false;
		Checker checker;
		Checker checkerv6;
		ItemState state = ItemState::Checking;
		int ping = 0;

	};

	std::vector<Item>::iterator findById(int id);
	std::vector<Item>::iterator findByProxy(const ProxyData &proxy);
	void setDeleted(int id, bool deleted);
	void updateView(const Item &item);
	void share(const ProxyData &proxy, bool qr = false);
	void saveDelayed();
	void refreshChecker(Item &item);

	void replaceItemWith(
		std::vector<Item>::iterator which,
		std::vector<Item>::iterator with);
	void replaceItemValue(
		std::vector<Item>::iterator which,
		const ProxyData &proxy);

	const not_null<Main::Account*> _account;
	Core::SettingsProxy &_settings;
	int _idCounter = 0;
	std::vector<Item> _list;
	rpl::event_stream<ItemView> _views;
	base::Timer _saveTimer;
	rpl::event_stream<ProxyData::Settings> _proxySettingsChanges;
	std::shared_ptr<Ui::Show> _show;

	ProxyData _lastSelectedProxy;
	bool _lastSelectedProxyUsed = false;

	rpl::lifetime _lifetime;

};
