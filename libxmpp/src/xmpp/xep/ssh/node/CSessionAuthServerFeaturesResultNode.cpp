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
#include <common/crypto/rsa/CRsaKey.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/xep/ssh/node/CSessionAuthServerFeaturesResultNode.h>

using namespace std;

CSessionAuthServerFeaturesResultNode::CSessionAuthServerFeaturesResultNode()
{
	try
	{
		SetName("ssh:session:auth:server:features:result");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");
		
		CXMLNode* pPublicKeyNode = new CXMLNode("public-key");

		CXMLNode* pNNode = new CXMLNode("n");
		CXMLNode* pENode = new CXMLNode("e");

		pPublicKeyNode->PushChild(pNNode);
		pPublicKeyNode->PushChild(pENode);

		PushChild(pPublicKeyNode);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionAuthServerFeaturesResultNodeException(CSessionAuthServerFeaturesResultNodeException::SASFRNEC_CONSTRUCTORERROR);
	}
}
CSessionAuthServerFeaturesResultNode::~CSessionAuthServerFeaturesResultNode()
{
}

void CSessionAuthServerFeaturesResultNode::GetPublicKey(CRsaKey* pRsaKey) const
{
	CBuffer NBuffer, EBuffer;
	CBase64 Base64;

	CXMLNode* pPublicKeyNode = GetChild("public-key");

	Base64.From64(pPublicKeyNode->GetChild("n")->GetData(), &NBuffer);
	Base64.From64(pPublicKeyNode->GetChild("e")->GetData(), &EBuffer);

	pRsaKey->SetPublicKey(EBuffer, NBuffer);

}

void CSessionAuthServerFeaturesResultNode::SetPublicKey(const CRsaKey& rRsaKey)
{
	CBuffer NBuffer, EBuffer;
	string NBase64, EBase64;
	CBase64 Base64;
	
	CXMLNode* pPublicKeyNode = GetChild("public-key");

	rRsaKey.GetE(&EBuffer);
	rRsaKey.GetN(&NBuffer);
	
	Base64.To64(&NBuffer, NBase64);
	Base64.To64(&EBuffer, EBase64);
	
	pPublicKeyNode->GetChild("n")->SetData(NBase64.c_str(), NBase64.size());
	pPublicKeyNode->GetChild("e")->SetData(EBase64.c_str(), EBase64.size());
}

CSessionAuthServerFeaturesResultNodeException::CSessionAuthServerFeaturesResultNodeException(int code) : CException(code)
{}

CSessionAuthServerFeaturesResultNodeException::~CSessionAuthServerFeaturesResultNodeException() throw()
{}
	
const char* CSessionAuthServerFeaturesResultNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SASFRNEC_CONSTRUCTORERROR:
		return "CSessionAuthServerFeaturesResultNode::Constructor() error";

	default:
		return "CSessionAuthServerFeaturesResultNode: Unknown error";
	}
}
