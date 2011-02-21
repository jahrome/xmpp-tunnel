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

#ifndef __CSESSIONKEYEXCHANGEDONODE_H__
#define __CSESSIONKEYEXCHANGEDONODE_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CSessionKeyExchangeDoNode : public CXMLNode
{
public:
	CSessionKeyExchangeDoNode();	
	virtual ~CSessionKeyExchangeDoNode();
	
	void GetPublicKey(CRsaKey* pRsaKey) const;
	void SetPublicKey(const CRsaKey& rRsaKey);
	
	void GetPlainKey1(CBuffer* pPlainKey1Buffer) const;
	void SetPlainKey1(CBuffer& pPlainKey1Buffer);
};
 
class CSessionKeyExchangeDoNodeException : public CException
{
public:
	enum SessionKeyExchangeDoNodeExceptionCode
	{
		SKEDNEC_CONSTRUCTORERROR
	};

public:
	CSessionKeyExchangeDoNodeException(int code);
	virtual ~CSessionKeyExchangeDoNodeException() throw();

	virtual const char* what() const throw();
};

#endif // __CSESSIONKEYEXCHANGEDONODE_H__
