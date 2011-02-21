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

#ifndef __CSESSIONKEYEXCHANGEDONENODE_H__
#define __CSESSIONKEYEXCHANGEDONENODE_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CSessionKeyExchangeDoneNode : public CXMLNode
{
public:
	CSessionKeyExchangeDoneNode();	
	virtual ~CSessionKeyExchangeDoneNode();

	void GetEncryptedKey2(CBuffer* pEncryptedKey2Buffer) const;
	void SetEncryptedKey2(CBuffer& rEncryptedKey2Buffer);
};
 
class CSessionKeyExchangeDoneNodeException : public CException
{
public:
	enum SessionKeyExchangeDoneNodeExceptionCode
	{
		SKEDNEC_CONSTRUCTORERROR
	};

public:
	CSessionKeyExchangeDoneNodeException(int code);
	virtual ~CSessionKeyExchangeDoneNodeException() throw();

	virtual const char* what() const throw();
};

#endif // __CSESSIONKEYEXCHANGEDONENODE_H__
