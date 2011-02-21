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

#ifndef __CXEPSSHD_H__
#define __CXEPSSHD_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/crypto/aes/CAes.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/thread/CThread.h>

#include <xmpp/core/CXMPPCore.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/xep/ssh/auth/CAuthentication.h>
#include <xmpp/xep/ssh/virtualshell/CVirtualShell.h>
#include <xmpp/xep/xibb/CXEPxibb.h>

using namespace std;

class CXEPsshd : public CObject
{
private:
	struct SSessionParam
	{
		CXEPxibb* pXEPxibb;
		CJid Jid;
		u16 localCid;
		u16 shellSid;
		CRsaKey* pServerAuthKey;
		CAes AesOnChannel;
		CAes AesOnShell;
		CAuthentication Authentication;
		CVirtualShell VirtualShell;
	};

public:
	CXEPsshd();
	virtual ~CXEPsshd();

	void SetServerAuthKey(CRsaKey* pServerAuthKey);

	void Attach(CXMPPCore* pXMPPCore);
	void Detach();

protected:
	void StartSession(const CJid& rJid, u16 localCid) throw();
	
private:
	static void* SessionManagerJob(void* pvThis) throw();
	static void* SessionJob(void* pvSSessionParam) throw();

	static void* InShellJob(void* pvSSessionParam) throw();
	static void* OutShellJob(void* pvSSessionParam) throw();

	static void SessionKeyExchange(SSessionParam* pSessionParam);
	static void SessionAuthServer(SSessionParam* pSessionParam);
	static void SessionAuthClient(SSessionParam* pSessionParam);
	static void SessionShell(SSessionParam* pSessionParam);
	
private:
	CThread ThreadSessionManagerJob;
	CThread ThreadSessionJob;

private:
	CXMPPCore* pXMPPCore;
	CXEPxibb XEPxibb;
	CRsaKey* pServerAuthKey;
};
 
class CXEPsshdException : public CException
{
public:
	enum XEPsshdExceptionCode
	{
		XEPSSHDEC_CONSTRUCTORERROR,
		XEPSSHDEC_DESTRUCTORERROR,
		XEPSSHDEC_SETSERVERAUTHKEYERROR,
		XEPSSHDEC_ATTACHERROR,
		XEPSSHDEC_DETACHERROR,
		XEPSSHDEC_SESSIONKEYEXCHANGEERROR,
		XEPSSHDEC_SESSIONAUTHSERVERERROR,
		XEPSSHDEC_SESSIONAUTHCLIENTERROR,
		XEPSSHDEC_SESSIONMANAGERJOBERROR,
		XEPSSHDEC_INSHELLJOBERROR,
		XEPSSHDEC_OUTSHELLJOBERROR
	};

public:
	CXEPsshdException(int code);
	virtual ~CXEPsshdException() throw();

	virtual const char* what() const throw();
};

#endif // __CXEPSSHD_H__
