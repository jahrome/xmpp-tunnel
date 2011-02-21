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

#include <xmpp/xep/ssh/node/CSessionKeyExchangeStartNode.h>

using namespace std;

CSessionKeyExchangeStartNode::CSessionKeyExchangeStartNode()
{
	try
	{
		SetName("ssh:session:keyexchange:start");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionKeyExchangeStartNodeException(CSessionKeyExchangeStartNodeException::SKESNEC_CONSTRUCTORERROR);
	}
}
CSessionKeyExchangeStartNode::~CSessionKeyExchangeStartNode()
{
}

CSessionKeyExchangeStartNodeException::CSessionKeyExchangeStartNodeException(int code) : CException(code)
{}

CSessionKeyExchangeStartNodeException::~CSessionKeyExchangeStartNodeException() throw()
{}
	
const char* CSessionKeyExchangeStartNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SKESNEC_CONSTRUCTORERROR:
		return "CSessionKeyExchangeStartNode::Constructor() error";

	default:
		return "CSessionKeyExchangeStartNode: Unknown error";
	}
}
