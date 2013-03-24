/*
 * WPA Supplicant / Haiku entrypoint
 * Copyright (c) 2011, Michael Lotz <mmlr@mlotz.ch>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <Application.h>
#include <Locker.h>
#include <MessageQueue.h>
#include <MessageRunner.h>
#include <NetworkDevice.h>
#include <ObjectList.h>
#include <String.h>

#include <net_notifications.h>

#include "WirelessConfigDialog.h"
#include "WPASupplicant.h" // private header currently inside Haiku

#include <new>

extern "C" {
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/defs.h"

#include "config.h"
#include "notify.h"
#include "notify_haiku.h"
#include "wpa_supplicant_i.h"
}

extern "C" {
#include <net/if_types.h>
#include <net80211/ieee80211_ioctl.h>
#include <sys/sockio.h>
}


static const uint32 kMsgJoinTimeout = 'jnto';


typedef	bool (*StateChangeCallback)(const wpa_supplicant *interface,
	BMessage *message, void *data);


class StateChangeWatchingEntry {
public:
								StateChangeWatchingEntry(
									const wpa_supplicant *interface,
									StateChangeCallback callback,
									void *data);

		bool					Match(const wpa_supplicant *interface,
									StateChangeCallback callback,
									void *data);

		bool					MessageReceived(
									const wpa_supplicant *interface,
									BMessage *message);

private:
		const wpa_supplicant *	fInterface;
		StateChangeCallback		fCallback;
		void *					fData;
};


StateChangeWatchingEntry::StateChangeWatchingEntry(
	const wpa_supplicant *interface, StateChangeCallback callback, void *data)
	:
	fInterface(interface),
	fCallback(callback),
	fData(data)
{
}


bool
StateChangeWatchingEntry::Match(const wpa_supplicant *interface,
	StateChangeCallback callback, void *data)
{
	return fInterface == interface && fCallback == callback && fData == data;
}


bool
StateChangeWatchingEntry::MessageReceived(const wpa_supplicant *interface,
	BMessage *message)
{
	if (interface != fInterface)
		return false;

	return fCallback(interface, message, fData);
}


class WPASupplicantApp : public BApplication {
public:
								WPASupplicantApp();
virtual							~WPASupplicantApp();

		status_t				InitCheck();

virtual	void					ReadyToRun();
virtual	void					MessageReceived(BMessage *message);

		status_t				RunSupplicantInMainThread();

private:
static	int32					_SupplicantThread(void *data);
static	void					_EventLoopProcessEvents(int sock,
									void *eventLoopContext, void *data);

		status_t				_EnqueueAndNotify(BMessage *message);
		status_t				_NotifyEventLoop();

		status_t				_JoinNetwork(BMessage *message);
		status_t				_LeaveNetwork(BMessage *message);

		status_t				_NotifyNetworkEvent(BMessage *message);

static	bool					_InterfaceStateChangeCallback(
									const wpa_supplicant *interface,
									BMessage *message, void *data);

		status_t				_StartWatchingInterfaceChanges(
									const wpa_supplicant *interface,
									StateChangeCallback callback, void *data);
		status_t				_StopWatchingInterfaceChanges(
									const wpa_supplicant *interface,
									StateChangeCallback callback, void *data);
		void					_NotifyInterfaceStateChanged(BMessage *message);

static	void					_SendReplyIfNeeded(BMessage &message,
									status_t status);

		status_t				fInitStatus;
		thread_id				fSupplicantThread;
		BMessageQueue			fEventQueue;

		int						fNotifySockets[2];

		BObjectList<StateChangeWatchingEntry>
								fWatchingEntryList;
		BLocker					fWatchingEntryListLocker;

		wpa_global *			fWPAGlobal;
		wpa_params				fWPAParameters;
};


WPASupplicantApp::WPASupplicantApp()
	:
	BApplication(kWPASupplicantSignature),
	fInitStatus(B_NO_INIT),
	fSupplicantThread(-1),
	fWPAGlobal(NULL)
{
	fNotifySockets[0] = fNotifySockets[1] = -1;

	fInitStatus = BApplication::InitCheck();
	if (fInitStatus != B_OK)
		return;

	memset(&fWPAParameters, 0, sizeof(fWPAParameters));
	//fWPAParameters.wpa_debug_level = MSG_DEBUG;

	fWPAGlobal = wpa_supplicant_init(&fWPAParameters);
	if (fWPAGlobal == NULL) {
		fInitStatus = B_ERROR;
		return;
	}

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fNotifySockets) != 0) {
		fInitStatus = errno;
		return;
	}
}


WPASupplicantApp::~WPASupplicantApp()
{
	if (fWPAGlobal == NULL)
		return;

	wpa_supplicant_terminate_proc(fWPAGlobal);

	// Wake the event loop up so it'll process the quit request and exit.
	_NotifyEventLoop();

	int32 result;
	wait_for_thread(fSupplicantThread, &result);

	wpa_supplicant_deinit(fWPAGlobal);

	close(fNotifySockets[0]);
	close(fNotifySockets[1]);
}


status_t
WPASupplicantApp::InitCheck()
{
	return fInitStatus;
}


void
WPASupplicantApp::ReadyToRun()
{
	fSupplicantThread = spawn_thread(_SupplicantThread,
		"wpa_supplicant thread", B_NORMAL_PRIORITY, this);
	if (fSupplicantThread < 0 || resume_thread(fSupplicantThread))
		PostMessage(B_QUIT_REQUESTED);
}


void
WPASupplicantApp::MessageReceived(BMessage *message)
{
	switch (message->what) {
		case kMsgWPAJoinNetwork:
		{
			uint32 authMode = B_NETWORK_AUTHENTICATION_NONE;
			status_t status = message->FindUInt32("authentication", &authMode);
			if (status != B_OK || !message->HasString("name")
				|| (authMode > B_NETWORK_AUTHENTICATION_NONE
					&& !message->HasString("password"))) {

				status = wireless_config_dialog(*message);
				if (status != B_OK) {
					_SendReplyIfNeeded(*message, status);
					return;
				}
			}

			_EnqueueAndNotify(DetachCurrentMessage());
				// The event processing code will send the reply.
			return;
		}

		case kMsgWPALeaveNetwork:
		{
			_EnqueueAndNotify(DetachCurrentMessage());
				// The event processing code will send the reply.
			return;
		}

		case B_NETWORK_MONITOR:
		{
			_EnqueueAndNotify(DetachCurrentMessage());
			return;
		}

		case kMsgSupplicantStateChanged:
		{
			_NotifyInterfaceStateChanged(message);
			return;
		}

		case kMsgJoinTimeout:
		{
			const wpa_supplicant *interface;
			if (message->FindPointer("interface", (void **)&interface) != B_OK)
				return;

			StateChangeCallback callback;
			if (message->FindPointer("callback", (void **)&callback) != B_OK)
				return;

			void *data;
			if (message->FindPointer("data", (void **)&data) != B_OK)
				return;

			if (_StopWatchingInterfaceChanges(interface, callback, data)
					== B_OK) {
				// The watch entry was still there, so no reply has been sent
				// yet. We do that now by calling the callback with the timeout
				// message.
				callback(interface, message, data);
			}

			return;
		}
	}

	BApplication::MessageReceived(message);
}


int32
WPASupplicantApp::_SupplicantThread(void *data)
{
	WPASupplicantApp *app = (WPASupplicantApp *)data;

	// Register our notify socket with the polling event loop.
	if (eloop_register_read_sock(app->fNotifySockets[0],
			_EventLoopProcessEvents, app->fWPAGlobal, app) != 0) {
		return B_ERROR;
	}

	wpa_supplicant_run(app->fWPAGlobal);

	eloop_unregister_read_sock(app->fNotifySockets[0]);

	// There are two reasons why the supplicant thread quit:
	// 1.	The event loop was terminated because of a signal or error and the
	//		application is still there and running.
	// 2.	The app has quit and stopped the event loop.
	//
	// In case of 2. we're done, but in case of 1. we need to quit the still
	// running application. We use the app messenger to reach the app if it is
	// still running. If it already quit the SendMessage() will simply fail.

	be_app_messenger.SendMessage(B_QUIT_REQUESTED);
	return B_OK;
}


status_t
WPASupplicantApp::_EnqueueAndNotify(BMessage *message)
{
	if (!fEventQueue.Lock())
		return B_ERROR;

	fEventQueue.AddMessage(message);
	fEventQueue.Unlock();

	return _NotifyEventLoop();
}


status_t
WPASupplicantApp::_NotifyEventLoop()
{
	// This will interrupt the event loop and cause the message queue to be
	// processed through the installed handler.
	uint8 byte = 0;
	ssize_t written = write(fNotifySockets[1], &byte, sizeof(byte));
	if (written < 0)
		return written;

	return written == sizeof(byte) ? B_OK : B_ERROR;
}


void
WPASupplicantApp::_EventLoopProcessEvents(int sock, void *eventLoopContext,
	void *data)
{
	// This function is called from the event loop only.

	WPASupplicantApp *app = (WPASupplicantApp *)data;

	uint8 bytes[25];
	read(app->fNotifySockets[0], bytes, sizeof(bytes));
		// discard them, they are just here to wake the event loop

	BMessageQueue &queue = app->fEventQueue;
	if (!queue.Lock())
		return;

	while (true) {
		BMessage *message = queue.FindMessage((int32)0);
		if (message == NULL)
			break;

		queue.RemoveMessage(message);

		bool needsReply = false;
		bool deleteMessage = true;
		status_t status = B_MESSAGE_NOT_UNDERSTOOD;
		switch (message->what) {
			case kMsgWPAJoinNetwork:
				status = app->_JoinNetwork(message);
				needsReply = status != B_OK;
				deleteMessage = needsReply;
				break;

			case kMsgWPALeaveNetwork:
				status = app->_LeaveNetwork(message);
				needsReply = status != B_OK;
				deleteMessage = needsReply;
				break;

			case B_NETWORK_MONITOR:
				app->_NotifyNetworkEvent(message);
				break;
		}

		if (needsReply)
			_SendReplyIfNeeded(*message, status);
		if (deleteMessage)
			delete message;
	}

	queue.Unlock();
}


status_t
WPASupplicantApp::_JoinNetwork(BMessage *message)
{
	const char *interfaceName = NULL;
	status_t status = message->FindString("device", &interfaceName);
	if (status != B_OK)
		return status;

	// Check if we already registered this interface.
	wpa_supplicant *interface = wpa_supplicant_get_iface(fWPAGlobal,
		interfaceName);
	if (interface == NULL) {
		wpa_interface interfaceOptions;
		memset(&interfaceOptions, 0, sizeof(wpa_interface));

		interfaceOptions.ifname = interfaceName;

		interface = wpa_supplicant_add_iface(fWPAGlobal, &interfaceOptions);
		if (interface == NULL)
			return B_NO_MEMORY;
	} else {
		// Disable everything
		wpa_supplicant_disable_network(interface, NULL);

		// Try to remove any previous network
		wpa_ssid *network = wpa_config_get_network(interface->conf, 0);
		if (network != NULL) {
			wpas_notify_network_removed(interface, network);
			wpa_config_remove_network(interface->conf, network->id);
		}		
	}

	const char *networkName = NULL;
	status = message->FindString("name", &networkName);
	if (status != B_OK)
		return status;

	uint32 authMode = B_NETWORK_AUTHENTICATION_NONE;
	status = message->FindUInt32("authentication", &authMode);
	if (status != B_OK)
		return status;

	const char *password = NULL;
	if (authMode > B_NETWORK_AUTHENTICATION_NONE) {
		status = message->FindString("password", &password);
		if (status != B_OK)
			return status;
	}

	wpa_ssid *network = wpa_config_add_network(interface->conf);
	if (network == NULL)
		return B_NO_MEMORY;

	wpas_notify_network_added(interface, network);

	network->disabled = 1;
	wpa_config_set_network_defaults(network);

	// Fill in the info from the join request

	// The format includes the quotes
	BString value;
	value = "\"";
	value += networkName;
	value += "\"";
	int result = wpa_config_set(network, "ssid", value.String(), 0);

	if (result == 0)
		result = wpa_config_set(network, "scan_ssid", "1", 1);

	if (authMode >= B_NETWORK_AUTHENTICATION_WPA) {
		if (result == 0)
			result = wpa_config_set(network, "proto", "WPA RSN", 2);
		if (result == 0)
			result = wpa_config_set(network, "key_mgmt", "WPA-PSK", 3);
		if (result == 0)
			result = wpa_config_set(network, "pairwise", "CCMP TKIP NONE", 4);
		if (result == 0) {
			result = wpa_config_set(network, "group",
				"CCMP TKIP WEP104 WEP40", 5);
		}
	} else {
		// Open or WEP.
		if (result == 0)
			result = wpa_config_set(network, "key_mgmt", "NONE", 6);
	}

	if (result == 0) {
		if (authMode == B_NETWORK_AUTHENTICATION_WEP) {
			if (strncmp("0x", password, 2) == 0) {
				// interpret as hex key
				// TODO: make this non-ambiguous
				result = wpa_config_set(network, "wep_key0", password + 2, 7);
			} else {
				value = "\"";
				value += password;
				value += "\"";
				result = wpa_config_set(network, "wep_key0", value.String(), 8);
			}

			if (result == 0)
				result = wpa_config_set(network, "wep_tx_keyidx", "0", 9);
		} else if (authMode >= B_NETWORK_AUTHENTICATION_WPA) {
			// WPA/WPA2
			value = "\"";
			value += password;
			value += "\"";
			result = wpa_config_set(network, "psk", value.String(), 10);

			if (result == 0) {
				// We need to actually "apply" the PSK
				wpa_config_update_psk(network);
			}
		}
	}

	if (result != 0) {
		wpas_notify_network_removed(interface, network);
		wpa_config_remove_network(interface->conf, network->id);
		return B_ERROR;
	}

	// Set up watching for the completion event
	_StartWatchingInterfaceChanges(interface, _InterfaceStateChangeCallback,
		message);

	// Now attempt to connect
	wpa_supplicant_select_network(interface, network);

	// Use a message runner to return a timeout and stop watching after a while
	BMessage timeout(kMsgJoinTimeout);
	timeout.AddPointer("interface", interface);
	timeout.AddPointer("callback", (void *)_InterfaceStateChangeCallback);
	timeout.AddPointer("data", message);

	BMessageRunner::StartSending(be_app_messenger, &timeout,
		15 * 1000 * 1000, 1);

	return B_OK;
}


status_t
WPASupplicantApp::_LeaveNetwork(BMessage *message)
{
	const char *interfaceName = NULL;
	status_t status = message->FindString("device", &interfaceName);
	if (status != B_OK)
		return status;

	wpa_supplicant *interface = wpa_supplicant_get_iface(fWPAGlobal,
		interfaceName);
	if (interface == NULL)
		return B_ENTRY_NOT_FOUND;

	if (wpa_supplicant_remove_iface(fWPAGlobal, interface) != 0)
		return B_ERROR;

	return B_OK;
}


status_t
WPASupplicantApp::_NotifyNetworkEvent(BMessage *message)
{
	// Verify that the interface is still there.
	BString interfaceName;
	if (message->FindString("interface", &interfaceName) != B_OK)
		return B_ERROR;

	interfaceName.Prepend("/dev/");
	wpa_supplicant *interface = wpa_supplicant_get_iface(fWPAGlobal,
		interfaceName.String());
	if (interface == NULL)
		return B_ENTRY_NOT_FOUND;

	void (*callback)(void *context, void *data, int opcode) = NULL;
	status_t result = message->FindPointer("callback", (void **)&callback);
	if (result != B_OK)
		return result;

	void *context = NULL;
	result = message->FindPointer("context", &context);
	if (result != B_OK)
		return result;

	void *data = NULL;
	message->FindPointer("data", &data);

	callback(context, data, message->FindInt32("opcode"));
	return B_OK;
}


bool
WPASupplicantApp::_InterfaceStateChangeCallback(const wpa_supplicant *interface,
	BMessage *message, void *data)
{
	// We wait for the completion state notification
	// TODO: We should also use the disconnect as an error case when joining,
	// but due to the event queue being serialized any disconnect happening
	// due to a new connect attempt would trigger that state. Either we need
	// to have the disconnect happen synchronously before joining again or
	// we need a way to discern one disconnect from the other, for example if
	// there was a way to tell from which network we disconnected.

	BMessage *originalMessage = (BMessage *)data;

	int32 newState;
	status_t result = B_ERROR;
	if (message->what == kMsgJoinTimeout)
		result = B_TIMED_OUT;
	else if (message->FindInt32("newState", &newState) == B_OK) {
		switch (newState) {
			case WPA_COMPLETED:
			{
				if (originalMessage->what != kMsgWPAJoinNetwork)
					return false;

				result = B_OK;
				break;
			}

			case WPA_DISCONNECTED:
			{
				if (originalMessage->what != kMsgWPALeaveNetwork)
					return false;

				result = B_OK;
				break;
			}

			default:
				return false;
		}
	}

	_SendReplyIfNeeded(*originalMessage, result);
	delete originalMessage;
	return true;
}


status_t
WPASupplicantApp::_StartWatchingInterfaceChanges(
	const wpa_supplicant *interface, StateChangeCallback callback, void *data)
{
	StateChangeWatchingEntry *entry
		= new(std::nothrow) StateChangeWatchingEntry(interface, callback, data);
	if (entry == NULL)
		return B_NO_MEMORY;

	if (!fWatchingEntryListLocker.Lock()) {
		delete entry;
		return B_ERROR;
	}

	status_t result = B_OK;
	if (!fWatchingEntryList.AddItem(entry)) {
		result = B_ERROR;
		delete entry;
	}

	fWatchingEntryListLocker.Unlock();
	return result;
}


status_t
WPASupplicantApp::_StopWatchingInterfaceChanges(
	const wpa_supplicant *interface, StateChangeCallback callback, void *data)
{
	if (!fWatchingEntryListLocker.Lock())
		return B_ERROR;

	bool found = false;
	for (int32 i = 0; i < fWatchingEntryList.CountItems(); i++) {
		if (fWatchingEntryList.ItemAt(i)->Match(interface, callback, data)) {
			delete fWatchingEntryList.RemoveItemAt(i);
			found = true;
			i--;
		}
	}

	fWatchingEntryListLocker.Unlock();
	return found ? B_OK : B_ENTRY_NOT_FOUND;
}


void
WPASupplicantApp::_NotifyInterfaceStateChanged(BMessage *message)
{
	const wpa_supplicant *interface;
	if (message->FindPointer("interface", (void **)&interface) != B_OK)
		return;

	if (!fWatchingEntryListLocker.Lock())
		return;

	for (int32 i = 0; i < fWatchingEntryList.CountItems(); i++) {
		StateChangeWatchingEntry *entry = fWatchingEntryList.ItemAt(i);
		if (entry->MessageReceived(interface, message)) {
			delete fWatchingEntryList.RemoveItemAt(i);
			i--;
		}
	}

	fWatchingEntryListLocker.Unlock();
}


void
WPASupplicantApp::_SendReplyIfNeeded(BMessage &message, status_t status)
{
	if (!message.IsSourceWaiting())
		return;

	BMessage reply;
	reply.AddInt32("status", status);
	message.SendReply(&reply);
}


int
main(int argc, char *argv[])
{
	WPASupplicantApp *app = new(std::nothrow) WPASupplicantApp();
	if (app == NULL)
		return B_NO_MEMORY;
	if (app->InitCheck() != B_OK)
		return app->InitCheck();

	app->Run();
	delete app;
	return 0;
}
