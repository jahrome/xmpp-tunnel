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

#ifndef __CSESSIONKEYEXCHANGEFEATURESRESULTNODE_H__
#define __CSESSIONKEYEXCHANGEFEATURESRESULTNODE_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CSessionKeyExchangeFeaturesResultNode : public CXMLNode
{
public:
	CSessionKeyExchangeFeaturesResultNode();	
	virtual ~CSessionKeyExchangeFeaturesResultNode();
};
 
class CSessionKeyExchangeFeaturesResultNodeException : public CException
{
public:
	enum SessionKeyExchangeFeaturesResultNodeExceptionCode
	{
		SKEFRNEC_CONSTRUCTORERROR
	};

public:
	CSessionKeyExchangeFeaturesResultNodeException(int code);
	virtual ~CSessionKeyExchangeFeaturesResultNodeException() throw();

	virtual const char* what() const throw();
};

#endif // __CSESSIONKEYEXCHANGEFEATURESRESULTNODE_H__
