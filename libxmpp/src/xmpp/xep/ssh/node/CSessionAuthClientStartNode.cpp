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
 
#include <iostream>
#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/xep/ssh/node/CSessionAuthClientStartNode.h>

using namespace std;

CSessionAuthClientStartNode::CSessionAuthClientStartNode()
{
	try
	{
		SetName("ssh:session:auth:client:start");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");
		
		CXMLNode* pUserNameNode = new CXMLNode("username");
		CXMLNode* pPasswordNode = new CXMLNode("password");
	
	
		PushChild(pUserNameNode);
		PushChild(pPasswordNode);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionAuthClientStartNodeException(CSessionAuthClientStartNodeException::SACSNEC_CONSTRUCTORERROR);
	}
}
CSessionAuthClientStartNode::~CSessionAuthClientStartNode()
{
}

const string& CSessionAuthClientStartNode::GetUserName() const
{
	return GetChild("username")->GetData();
}

const string& CSessionAuthClientStartNode::GetPassword() const
{
	return GetChild("password")->GetData();
}

void CSessionAuthClientStartNode::SetUserName(const string& userName)
{
	GetChild("username")->SetData(userName.c_str(), userName.size());
}

void CSessionAuthClientStartNode::SetPassword(const string& password)
{
	GetChild("password")->SetData(password.c_str(), password.size());
}


CSessionAuthClientStartNodeException::CSessionAuthClientStartNodeException(int code) : CException(code)
{}

CSessionAuthClientStartNodeException::~CSessionAuthClientStartNodeException() throw()
{}
	
const char* CSessionAuthClientStartNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SACSNEC_CONSTRUCTORERROR:
		return "CSessionAuthClientStartNode::Constructor() error";

	default:
		return "CSessionAuthClientStartNode: Unknown error";
	}
}
