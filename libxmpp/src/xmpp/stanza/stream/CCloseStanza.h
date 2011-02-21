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

#ifndef __CCLOSESTANZA_H__
#define __CCLOSESTANZA_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>

using namespace std;

class CCloseStanza : public CStanza
{
public:
	CCloseStanza();
	virtual ~CCloseStanza();

	u32 GetKindOf() const;
	virtual void Build(CBuffer* pBuffer) const;
};

class CCloseStanzaException : public CException
{
public:
	enum CloseStanzaExceptionCode
	{
		CSEC_CONSTRUCTORERROR,
		CSEC_BUILDERROR
	};

public:
	CCloseStanzaException(int code);
	virtual ~CCloseStanzaException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CCLOSESTANZA_H__
