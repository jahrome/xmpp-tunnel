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

#ifndef __CSESSIONAUTHCLIENTSTARTNODE_H__
#define __CSESSIONAUTHCLIENTSTARTNODE_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CSessionAuthClientStartNode : public CXMLNode
{
public:
	CSessionAuthClientStartNode();	
	virtual ~CSessionAuthClientStartNode();
	
	const string& GetUserName() const;
	const string& GetPassword() const;

	void SetUserName(const string& userName);
	void SetPassword(const string& password);
};
 
class CSessionAuthClientStartNodeException : public CException
{
public:
	enum SessionAuthClientStartNodeExceptionCode
	{
		SACSNEC_CONSTRUCTORERROR,
		SACSNEC_GETUSERNAMEERROR,
		SACSNEC_GETPASSWORDERROR
	};

public:
	CSessionAuthClientStartNodeException(int code);
	virtual ~CSessionAuthClientStartNodeException() throw();

	virtual const char* what() const throw();
};

#endif // __CSESSIONAUTHCLIENTSTARTNODE_H__
