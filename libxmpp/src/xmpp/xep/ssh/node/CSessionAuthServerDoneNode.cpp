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

#include <xmpp/xep/ssh/node/CSessionAuthServerDoneNode.h>

using namespace std;

CSessionAuthServerDoneNode::CSessionAuthServerDoneNode()
{
	try
	{
		SetName("ssh:session:auth:server:done");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");
		
		CXMLNode* pSignatureNode = new CXMLNode("signature");
		PushChild(pSignatureNode);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionAuthServerDoneNodeException(CSessionAuthServerDoneNodeException::SASDNEC_CONSTRUCTORERROR);
	}
}
CSessionAuthServerDoneNode::~CSessionAuthServerDoneNode()
{
}

void CSessionAuthServerDoneNode::GetSignature(CBuffer* pSignature) const
{
	CBase64 Base64;
	Base64.From64(GetChild("signature")->GetData(), pSignature);
}

void CSessionAuthServerDoneNode::SetSignature(CBuffer& rSignature)
{
	string SignatureBase64;
	CBase64 Base64;

	Base64.To64(&rSignature, SignatureBase64);
	GetChild("signature")->SetData(SignatureBase64.c_str(), SignatureBase64.size());
}


CSessionAuthServerDoneNodeException::CSessionAuthServerDoneNodeException(int code) : CException(code)
{}

CSessionAuthServerDoneNodeException::~CSessionAuthServerDoneNodeException() throw()
{}
	
const char* CSessionAuthServerDoneNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SASDNEC_CONSTRUCTORERROR:
		return "CSessionAuthServerDoneNode::Constructor() error";

	default:
		return "CSessionAuthServerDoneNode: Unknown error";
	}
}
