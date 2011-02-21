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

#ifndef __CSUCCESSSTANZA_H__
#define __CSUCCESSSTANZA_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>

using namespace std;

class CSuccessStanza : public CStanza
{
public:
	CSuccessStanza();
	virtual ~CSuccessStanza();

	u32 GetKindOf() const;
};

class CSuccessStanzaException : public CException
{
public:
	enum SuccessStanzaExceptionCode
	{
		SSEC_CONSTRUCTORERROR
	};

public:
	CSuccessStanzaException(int code);
	virtual ~CSuccessStanzaException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CSUCCESSSTANZA_H__
