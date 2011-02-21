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

#include <expat.h>
#include <iostream>
#include <queue>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/thread/CMutex.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/xml/CXMPPParser.h>

using namespace std;

CXMPPParser::CXMPPParser()
{
	Init();
}

CXMPPParser::~CXMPPParser()
{
	try
	{
		Destroy();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
	}
}

void CXMPPParser::Init()
{
	try
	{
		Mutex.Lock();
		
		pCurrentNode = NULL;
		pRootNode = NULL;
		
		parser = XML_ParserCreate(NULL);

		if(parser == NULL)
		throw CXMPPParserException(CXMPPParserException::XPEC_CREATINGERROR);

		XML_SetUserData(parser, this);
		XML_SetElementHandler(parser, EventStartElement, EventEndElement);
		XML_SetCharacterDataHandler(parser, EventDataElement);
		Mutex.UnLock();
	}

	catch(exception& e)
	{
		Mutex.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_CREATINGERROR);
	}
}

void CXMPPParser::Destroy()
{
	try
	{
		Mutex.Lock();
		
		if(parser != NULL)
		{
			XML_ParserFree(parser);
			parser = NULL;
		}
		
		if(pRootNode != NULL)
		{
			delete pRootNode;
			pRootNode = NULL;
		}
		
		while(!XMLNodeQueue.empty())
		{
			delete XMLNodeQueue.front();
			XMLNodeQueue.pop();
		}
		
		Mutex.UnLock();
	}

	catch(exception& e)
	{
		Mutex.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_FREEINGERROR);
	}
}

void CXMPPParser::ReInit()
{
	Destroy();
	Init();
}

void CXMPPParser::Write(const CBuffer* pBuffer)
{
	try
	{
		Mutex.Lock();
		if(XML_Parse(parser, (char*) pBuffer->GetBuffer(), pBuffer->GetBufferSize(), 0) == XML_STATUS_ERROR)
		throw CXMPPParserException(CXMPPParserException::XPEC_PARSINGERROR);
		Mutex.UnLock();
	}
	
	catch(exception& e)
	{
		Mutex.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_PARSINGERROR);
	}
}

CXMLNode* CXMPPParser::GetXMLNode()
{
	try
	{
		Mutex.Lock();

		while(XMLNodeQueue.empty())
		Mutex.Wait();

		CXMLNode* pXMLNode = XMLNodeQueue.front();
		XMLNodeQueue.pop();

		Mutex.UnLock();
		return pXMLNode;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_GETSTANZAERROR);
	}
}

CObject::u32 CXMPPParser::GetNumXMLNode()
{
	Mutex.Lock();
	u32 size = XMLNodeQueue.size();
	Mutex.UnLock();

	return size;
}
void CXMPPParser::EventStartElement(void* pvThis, const char* name, const char** atts)
{
	CXMLNode* pXMLNode = NULL;

	try
	{
		CXMPPParser* This = (CXMPPParser*) pvThis;
		
		if(This->pCurrentNode == NULL)
		{
			pXMLNode = new CXMLNode();
			This->pCurrentNode = pXMLNode;
			This->pRootNode = pXMLNode;	
		}
		else
		{
			pXMLNode = new CXMLNode();
			This->pCurrentNode->PushChild(pXMLNode);
			This->pCurrentNode = pXMLNode;
		}
		
		pXMLNode->SetName(name);

		for(int i = 0 ; atts[i] != NULL ; i += 2)
		pXMLNode->SetAttribut(atts[i], atts[i + 1]);
	}
	
	catch(exception& e)
	{
		if(pXMLNode != NULL)
		delete pXMLNode;
		
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_PARSINGERROR);
	}
}

void CXMPPParser::EventDataElement(void* pvThis, const char* data, int len)
{
	try
	{
		CXMPPParser* This = (CXMPPParser*) pvThis;

		if(len > 0)
		This->pCurrentNode->AppendData(data, len);	
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_PARSINGERROR);
	}
}

void CXMPPParser::EventEndElement(void* pvThis, const char* name)
{
	try
	{
		CXMPPParser* This = (CXMPPParser*) pvThis;
		CXMLNode* pParent = This->pCurrentNode->GetParent();
		
		if(pParent == NULL)
		{
			delete This->pRootNode;
			This->pCurrentNode = NULL;
			This->pRootNode = NULL;
		}
		else
		if(pParent->GetParent() == NULL)
		{
			This->pCurrentNode->Detach();

			This->XMLNodeQueue.push(This->pCurrentNode);
			This->Mutex.Signal();

			This->pCurrentNode = pParent;
		}
		else
		{
			This->pCurrentNode = pParent;
		}

	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPParserException(CXMPPParserException::XPEC_PARSINGERROR);
	}
}

CXMPPParserException::CXMPPParserException(int code) : CException(code)
{}

CXMPPParserException::~CXMPPParserException() throw()
{}

const char* CXMPPParserException::what() const throw()
{
	switch(GetCode())
	{
	case XPEC_PARSINGERROR:
		return "CXMPPParserException: Parsing error";

	case XPEC_CREATINGERROR:
		return "CXMPPParserException: Creating error";

	case XPEC_FREEINGERROR:
		return "CXMPPParserException: Freeing error";

	case XPEC_GETSTANZAERROR:
		return "CXMPPParserException: Get stanza error";

	default:
		return "CCXMPPParserException: Unknown error";
	}
}

