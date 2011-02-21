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

#ifndef __CRESOXSERVER_H__
#define __CRESOXSERVER_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/thread/CThread.h>
#include <common/crypto/rsa/CRsaKey.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/xep/disco/CXEPdisco.h>
#include <xmpp/xep/ssh/CXEPsshd.h>

using namespace std;

class CResoxServer : public CObject
{
public:
	CResoxServer();
	virtual ~CResoxServer();

	void Run(const CJid* pJid, const CTCPAddress* pTCPAddress, CRsaKey& rRsaServerKey);
	void Stop();

		
private:
	CXMPPInstMsg XMPPInstMsg;
	
	CXEPdisco XEPdisco;
	CXEPsshd XEPsshd;
};

class CResoxServerException : public CException
{
public:
	enum ResoxServerExceptionCode
	{
		RSEC_CONSTRUCTORERROR,
		RSEC_RUNERROR,
		RSEC_PROCESSSTANZAERROR,
		RSEC_ONDISCOERROR
	};

	CResoxServerException(int code);
	virtual ~CResoxServerException() throw();

	virtual const char* what() const throw();

};

#endif // __CRESOXSERVER_H__
