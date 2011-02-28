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

#ifndef __CXEPSSH_H__
#define __CXEPSSH_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CXMPPCore.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CXEPxibb.h>

using namespace std;

class CXEPssh : public CObject
{
public:

	CXEPssh();
	virtual ~CXEPssh();

	void Attach(CXMPPCore* pXMPPCore);
	void Detach();

	void ConnectToSSH(const CJid& rRemoteJid);
	void Disconnect();

	void Login();
	
	void SetShellSize(u32 row, u32 column, u32 xpixel, u32 ypixel);
	void SendData(CBuffer* pBuffer);
	void ReceiveData(CBuffer* pBuffer);

	const CJid& GetRemoteJid() const;

private:
	void SessionAuthClient(const string& userName, const string& password);
	void SessionShell();
	
private:
	CXMPPCore* pXMPPCore;
	CXEPxibb XEPxibb;
	CJid RemoteJid;
	u16 channelId;
	u16 shellSid;
};
 
class CXEPsshException : public CException
{
public:
	enum XEPsshExceptionCode
	{
		XEPSSHEC_CONSTRUCTORERROR,
		XEPSSHEC_DESTRUCTORERROR,
		XEPSSHEC_ATTACHERROR,
		XEPSSHEC_DETACHERROR,
		XEPSSHEC_CONNECTTOSSHERROR,
		XEPSSHEC_DISCONNECTERROR,
		XEPSSHEC_SENDDATAERROR,
		XEPSSHEC_RECEIVEDATAERROR,
		XEPSSHEC_SETSHELLSIZEERROR,
		XEPSSHEC_SESSIONKEYEXCHANGEERROR,
		XEPSSHEC_SESSIONAUTHSERVERERROR,
		XEPSSHEC_SESSIONAUTHCLIENTERROR		
	};

public:
	CXEPsshException(int code);
	virtual ~CXEPsshException() throw();

	virtual const char* what() const throw();
};

#endif // __CXEPSSH_H__
