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

#ifndef __CXEPDISCO_H__
#define __CXEPDISCO_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/thread/CThread.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>

using namespace std;

class CXEPdisco : public CObject
{
public:
	CXEPdisco();
	virtual ~CXEPdisco();

	void Attach(CXMPPCore* pXMPPCore);
	void Detach();

	void Disco(vector<string>* pFeaturesList);
	void Disco(const CJid& rJid, vector<string>* pFeaturesList);

private:
	static void* OnDiscoJob(void* pvThis) throw();

private:
	CXMPPCore* pXMPPCore;

	CHandler DiscoHandler;
	CThread ThreadOnDisco;
};
 
class CXEPdiscoException : public CException
{
public:
	enum XEPdiscoExceptionCode
	{
		XEPDEC_CONSTRUCTORERROR,
		XEPDEC_DESTRUCTORERROR,
		XEPDEC_ATTACHERROR,
		XEPDEC_DETACHERROR,
		XEPDEC_DISCOERROR,
		XEPDEC_ONDISCOERROR
	};

public:
	CXEPdiscoException(int code);
	virtual ~CXEPdiscoException() throw();

	virtual const char* what() const throw();
};

#endif // __CXEPDISCO_H__
