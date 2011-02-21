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
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/xep/ssh/node/CSessionKeyExchangeDoNode.h>

using namespace std;

CSessionKeyExchangeDoNode::CSessionKeyExchangeDoNode()
{
	try
	{
		SetName("ssh:session:keyexchange:do");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");

		CXMLNode* pPublicKeyNode = new CXMLNode("public-key");
		CXMLNode* pPlainKey1Node = new CXMLNode("plain-key1");

		CXMLNode* pNNode = new CXMLNode("n");
		CXMLNode* pENode = new CXMLNode("e");

		pPublicKeyNode->PushChild(pNNode);
		pPublicKeyNode->PushChild(pENode);

		PushChild(pPublicKeyNode);
		PushChild(pPlainKey1Node);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionKeyExchangeDoNodeException(CSessionKeyExchangeDoNodeException::SKEDNEC_CONSTRUCTORERROR);
	}
}

CSessionKeyExchangeDoNode::~CSessionKeyExchangeDoNode()
{
}

void CSessionKeyExchangeDoNode::GetPublicKey(CRsaKey* pRsaKey) const
{
	CBuffer NBuffer, EBuffer;
	CBase64 Base64;

	CXMLNode* pPublicKeyNode = GetChild("public-key");

	Base64.From64(pPublicKeyNode->GetChild("n")->GetData(), &NBuffer);
	Base64.From64(pPublicKeyNode->GetChild("e")->GetData(), &EBuffer);

	pRsaKey->SetPublicKey(EBuffer, NBuffer);

}

void CSessionKeyExchangeDoNode::SetPublicKey(const CRsaKey& rRsaKey)
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

void CSessionKeyExchangeDoNode::GetPlainKey1(CBuffer* pPlainKey1Buffer) const
{
	CBase64 Base64;
	Base64.From64(GetChild("plain-key1")->GetData(), pPlainKey1Buffer);
}

void CSessionKeyExchangeDoNode::SetPlainKey1(CBuffer& rPlainKey1Buffer)
{
	string PlainKey1Base64;
	CBase64 Base64;

	Base64.To64(&rPlainKey1Buffer, PlainKey1Base64);
	GetChild("plain-key1")->SetData(PlainKey1Base64.c_str(), PlainKey1Base64.size());
}

CSessionKeyExchangeDoNodeException::CSessionKeyExchangeDoNodeException(int code) : CException(code)
{}

CSessionKeyExchangeDoNodeException::~CSessionKeyExchangeDoNodeException() throw()
{}
	
const char* CSessionKeyExchangeDoNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SKEDNEC_CONSTRUCTORERROR:
		return "CSessionKeyExchangeDoNode::Constructor() error";

	default:
		return "CSessionKeyExchangeDoNode: Unknown error";
	}
}
