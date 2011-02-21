/*
 *  XMPP-SSH is a XMPP protocol extension to provide several secure shell
 *  streams over the XMPP protocol between two Jabber entities using
 *  strong authentication, end-To-end encryption (RSA/AES) and X11
 *  forwarding.
 *
 *  Copyright (C) 2007 Adrien Pinet
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifndef __CRESOX_H__
#define __CRESOX_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/thread/CThread.h>

#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/im/CRoster.h>
#include <xmpp/im/CRosterItem.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/xep/disco/CXEPdisco.h>
#include <xmpp/xep/ssh/CXEPssh.h>

using namespace std;

class CResox : public CObject
{
public:
	CResox();
	~CResox();
	
	void ConnectTo(const CJid& xmppJid, const CTCPAddress& rTCPAddress);
	void ConnectToSSH(const CJid& sshJid, CRsaKey* pAuthServerKey);
	void Login(const string& userName, const string& password);

	void StartRosterEvent(CRoster* pRoster);
	bool OnRosterUpdated(CRoster* pRoster);
	void StopRosterEvent();

public:
	static void* InShellJob(void* pvThis) throw();
	static void* OutShellJob(void* pvThis) throw();
	
	static void InterceptSignal(int signal);
	
private:
	CJid xmppJid;
	CJid sshJid;

	CXMPPInstMsg XMPPInstMsg;	
	CXEPdisco XEPdisco;
	CXEPssh XEPssh;
	
	CThread ThreadInShellJob;
	CThread ThreadOutShellJob;
};

class CResoxException : public CException
{
public:
	enum ResoxExceptionCode
	{
		REC_RUNERROR,
		REC_1
	};

	CResoxException(int code);
	virtual ~CResoxException() throw();

	virtual const char* what() const throw();

};

#endif // __CRESOX_H__
