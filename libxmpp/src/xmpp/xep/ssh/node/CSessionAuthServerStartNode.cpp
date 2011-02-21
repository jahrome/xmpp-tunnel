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
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/xep/ssh/node/CSessionAuthServerStartNode.h>

using namespace std;

CSessionAuthServerStartNode::CSessionAuthServerStartNode()
{
	try
	{
		SetName("ssh:session:auth:server:start");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");
		
		CXMLNode* pChallengeNode = new CXMLNode("challenge");
		PushChild(pChallengeNode);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionAuthServerStartNodeException(CSessionAuthServerStartNodeException::SASSNEC_CONSTRUCTORERROR);
	}
}
CSessionAuthServerStartNode::~CSessionAuthServerStartNode()
{
}

void CSessionAuthServerStartNode::GetChallenge(CBuffer* pChallenge) const
{
	CBase64 Base64;
	Base64.From64(GetChild("challenge")->GetData(), pChallenge);
}

void CSessionAuthServerStartNode::SetChallenge(CBuffer& rChallenge)
{
	string ChallengeBase64;
	CBase64 Base64;

	Base64.To64(&rChallenge, ChallengeBase64);
	GetChild("challenge")->SetData(ChallengeBase64.c_str(), ChallengeBase64.size());
}

CSessionAuthServerStartNodeException::CSessionAuthServerStartNodeException(int code) : CException(code)
{}

CSessionAuthServerStartNodeException::~CSessionAuthServerStartNodeException() throw()
{}
	
const char* CSessionAuthServerStartNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SASSNEC_CONSTRUCTORERROR:
		return "CSessionAuthServerStartNode::Constructor() error";

	default:
		return "CSessionAuthServerStartNode: Unknown error";
	}
}
