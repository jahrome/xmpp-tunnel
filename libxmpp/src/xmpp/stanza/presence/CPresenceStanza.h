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

#ifndef __CPRESENCESTANZA_H__
#define __CPRESENCESTANZA_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>

using namespace std;

class CPresenceStanza : public CStanza
{
public:
	CPresenceStanza();
	virtual ~CPresenceStanza();

	u32 GetKindOf() const;
		
	void SetShow(const string& show);
	void SetStatus(const string& status);
	void SetPriority(const string& priority);

	const string& GetShow() const;
	const string& GetStatus() const;
	const string& GetPriority() const;

	bool IsAvailable() const;

private:
	string CONST_STRING_EMPTY;
};

class CPresenceStanzaException : public CException
{
public:
	enum PresenceStanzaExceptionCode
	{
		PSEC_CONSTRUCTORERROR,
		PSEC_SETSHOWERROR,
		PSEC_SETSTATUSERROR,
		PSEC_SETPRIORITYERROR
	};

public:
	CPresenceStanzaException(int code);
	virtual ~CPresenceStanzaException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CPRESENCESTANZA_H__
