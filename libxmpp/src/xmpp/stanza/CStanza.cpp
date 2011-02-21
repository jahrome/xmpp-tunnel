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

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>

using namespace std;

CStanza::CStanza()
{
	try
	{
		pXMLNode = new CXMLNode();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_CONSTRUCTORERROR);
	}
}

CStanza::~CStanza()
{
	try
	{
		if(pXMLNode != NULL)
		delete pXMLNode;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

CXMLNode* CStanza::DetachXMLNode()
{
	try
	{
		CXMLNode* pXMLNode = this->pXMLNode;
		this->pXMLNode = NULL;
		return pXMLNode;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_DETACHXMLNODEERROR);
	}
}

CXMLNode* CStanza::GetXMLNode() const
{
	try
	{
		return pXMLNode;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETXMLNODEERROR);
	}
}

void CStanza::AttachXMLNode(CXMLNode* pXMLNode)
{
	try
	{
		if(this->pXMLNode != NULL)
		delete this->pXMLNode;
	
		this->pXMLNode = pXMLNode;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_ATTACHXMLNODEERROR);
	}
}


CObject::u32 CStanza::GetKindOf() const
{
	try
	{
		if(GetName() == "stream:open")
		return SKO_OPEN;

		if(GetName() == "stream:features")
		return SKO_FEATURES;

		if(GetName() == "proceed")
		return SKO_PROCEED;

		if(GetName() == "starttls")
		return SKO_STARTTLS;

		if(GetName() == "iq")
		return SKO_IQ;

		if(GetName() == "message")
		return SKO_MESSAGE;

		if(GetName() == "presence")
		return SKO_PRESENCE;

		if(GetName() == "stream:close")
		return SKO_CLOSE;

		if(GetName() == "success")
		return SKO_SUCCESS;
		
		if(GetName() == "challenge")
		return SKO_CHALLENGE;
		
		if(GetName() == "response")
		return SKO_RESPONSE;
		
		return SKO_UNKNOWN;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETKINDOFERROR);
	}
}

void CStanza::Build(CBuffer* pBuffer) const
{
	try
	{
		pXMLNode->Build(pBuffer);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_BUILDERROR);
	}
}

const string& CStanza::GetNameSpace() const
{
	try
	{
		return pXMLNode->GetNameSpace();
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETNAMESPACEERROR);
	}
}

const string& CStanza::GetName() const
{
	try
	{
		return pXMLNode->GetName();
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETNAMEERROR);
	}
}

const string& CStanza::GetTo() const
{
	try
	{
		return pXMLNode->GetAttribut("to");
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETTOERROR);
	}
}

const string& CStanza::GetFrom() const
{
	try
	{
		return pXMLNode->GetAttribut("from");
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETFROMERROR);
	}
}

const string& CStanza::GetId() const
{
	try
	{
		return pXMLNode->GetAttribut("id");
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETIDERROR);
	}
}

const string& CStanza::GetType() const
{
	try
	{
		return pXMLNode->GetAttribut("type");
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETTYPEERROR);
	}
}

const string& CStanza::GetLang() const
{
	try
	{
		return pXMLNode->GetAttribut("xml:lang");
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETLANGERROR);
	}
}

void CStanza::SetNameSpace(const string& nameSpace)
{
	try
	{
		pXMLNode->SetNameSpace(nameSpace);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETNAMESPACEERROR);
	}
}

void CStanza::SetName(const string& name)
{
	try
	{
		pXMLNode->SetName(name);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETNAMEERROR);
	}
}

void CStanza::SetTo(const string& to)
{
	try
	{
		pXMLNode->SetAttribut("to", to);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETTOERROR);
	}
}

void CStanza::SetType(const string& type)
{
	try
	{
		pXMLNode->SetAttribut("type", type);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETTYPEERROR);
	}
}

void CStanza::SetLang(const string& lang)
{
	try
	{
		pXMLNode->SetAttribut("xml:lang", lang);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETLANGERROR);
	}
}

void CStanza::SetId(const string& id)
{
	try
	{
		pXMLNode->SetAttribut("id", id);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETIDERROR);
	}
}

void CStanza::SetData(const char data[], u32 len)
{
	try
	{
		pXMLNode->SetData(data, len);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETDATAERROR);
	}
}

void CStanza::AppendData(const char data[], u32 len)
{
	try
	{
		pXMLNode->AppendData(data, len);
	}
	
	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_APPENDDATAERROR);
	}
}

const string& CStanza::GetData() const
{
	try
	{
		return pXMLNode->GetData();
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETDATAERROR);
	}
}
void CStanza::SetAttribut(const string& attr, const string& value)
{
	try
	{
		pXMLNode->SetAttribut(attr, value);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_SETATTRIBUTERROR);
	}
}

const string& CStanza::GetAttribut(const string& attr) const
{
	try
	{
		return pXMLNode->GetAttribut(attr);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETATTRIBUTERROR);
	}
}

void CStanza::PushChild(CXMLNode* pXMLNode)
{
	try
	{
		this->pXMLNode->PushChild(pXMLNode);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_PUSHCHILDERROR);
	}
}

bool CStanza::IsExistChild(const string& name) const
{
	try
	{
		return pXMLNode->IsExistChild(name);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_ISEXISTCHILDERROR);
	}
}

bool CStanza::IsExistAttribut(const string& attr) const
{
	try
	{
		return pXMLNode->IsExistAttribut(attr);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_ISEXISTATTRIBUTERROR);
	}
}

CXMLNode* CStanza::GetChild(u32 index) const
{
	try
	{
		return pXMLNode->GetChild(index);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETCHILDERROR);
	}
}

CXMLNode* CStanza::GetChild(const string& name) const
{
	try
	{
		return pXMLNode->GetChild(name);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_GETCHILDERROR);
	}
}

CXMLNode* CStanza::PopChild(u32 index)
{
	try
	{
		return pXMLNode->PopChild(index);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_POPCHILDERROR);
	}
}

CXMLNode* CStanza::PopChild(const string& name)
{
	try
	{
		return pXMLNode->PopChild(name);
	}

	catch(CException& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStanzaException(CStanzaException::SEC_POPCHILDERROR);
	}
}

CStanzaException::CStanzaException(int code) : CException(code)
{}

CStanzaException::~CStanzaException() throw()
{}

const char* CStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case SEC_CONSTRUCTORERROR:
		return "CStanza::Constructor() error";
	
	case SEC_DESTRUCTORERROR:
		return "CStanza::Destructor() error";

	case SEC_DETACHXMLNODEERROR:
		return "CStanza::DetachXMLNode() error";
	
	case SEC_GETXMLNODEERROR:
		return "CStanza::GetXMLNode() error";

	case SEC_ATTACHXMLNODEERROR:
		return "CStanza::AttachXMLNode() error";

	case SEC_BUILDERROR:
		return "CStanza::Build() error";

	case SEC_GETKINDOFERROR:
		return "CStanza::GetKindOf() error";

	case SEC_SETTOERROR:
		return "CStanza::SetTo() error";

	case SEC_SETNAMEERROR:
		return "CStanza::SetName() error";

	case SEC_SETNAMESPACEERROR:
		return "CStanza::SetNameSpace() error";

	case SEC_SETIDERROR:
		return "CStanza::SetId() error";

	case SEC_SETTYPEERROR:
		return "CStanza::SetType() error";

	case SEC_SETLANGERROR:
		return "CStanza::SetLang() error";

	case SEC_SETDATAERROR:
		return "CStanza::SetData() error";

	case SEC_SETATTRIBUTERROR:
		return "CStanza::SetAttribut() error";

	case SEC_GETTOERROR:
		return "CStanza::GetTo() error";

	case SEC_GETNAMEERROR:
		return "CStanza::getName() error";

	case SEC_GETNAMESPACEERROR:
		return "CStanza::GetNameSpace() error";

	case SEC_GETFROMERROR:
		return "CStanza::GetFrom() error";

	case SEC_GETIDERROR:
		return "CStanza::GetId() error";

	case SEC_GETTYPEERROR:
		return "CStanza::GetType() error";

	case SEC_GETLANGERROR:
		return "CStanza::GetLang() error";

	case SEC_GETDATAERROR:
		return "CStanza::GetData() error";
	
	case SEC_GETATTRIBUTERROR:
		return "CStanza::GetAttribut() error";

	case SEC_GETCHILDERROR:
		return "CStanza::GetChild() error";

	case SEC_APPENDDATAERROR:
		return "CStanza::AppendData() error";

	case SEC_PUSHCHILDERROR:
		return "CStanza::PushChild() error";

	case SEC_ISEXISTCHILDERROR:
		return "CStanza::IsExistChild() error";

	case SEC_ISEXISTATTRIBUTERROR:
		return "CStanza::IsExistAttribut() error";

	case SEC_POPCHILDERROR:
		return "CStanza::PopChild() error";

	default:
		return "CStanza: Unknown error";
	}
}

