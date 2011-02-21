/*
 *  KnotTTY is a remote secure shell using the new public key exchange protocol
 *  with the Braid Group Cryptosystems
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

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

using namespace std;

CXMLParser::CXMLParser()
{}

CXMLParser::~CXMLParser()
{}

void CXMLParser::Parse(CBuffer* pBuffer, CXMLNode* pXMLNode)
{
	try
	{
		SContext Context;
		XML_Parser parser = XML_ParserCreate(NULL);

		if(parser == NULL)
		throw CXMLParserException(CXMLParserException::XPEC_PARSEERROR);
		
		// we erase the pXMLNode
		pXMLNode->Destroy();
		
		Context.pCurrentNode = pXMLNode;
		Context.isRootNode = true;

		XML_SetUserData(parser, &Context);
		XML_SetElementHandler(parser, EventStartElement, EventEndElement);
		XML_SetCharacterDataHandler(parser, EventDataElement);
	
		if(XML_Parse(parser, (char*) pBuffer->GetBuffer(), pBuffer->GetBufferSize(), 0) == XML_STATUS_ERROR)
		{
			XML_ParserFree(parser);
			throw CXMLParserException(CXMLParserException::XPEC_PARSEERROR);
		}
		
		XML_ParserFree(parser);	
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		throw CXMLParserException(CXMLParserException::XPEC_PARSEERROR);
	}
}
	
void CXMLParser::EventDataElement(void* pvContext, const char* name, int len)
{
	try
	{
		SContext* pContext = (SContext*) pvContext;
		
		pContext->pCurrentNode->AppendData(name, len);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		throw CXMLParserException(CXMLParserException::XPEC_EVENTDATAELEMENTERROR);
	}
}

void CXMLParser::EventStartElement(void* pvContext, const char* name, const char** atts)
{
	try
	{
		SContext* pContext = (SContext*) pvContext;
		CXMLNode* pSubNode;
		
		if(pContext->isRootNode)
		{
			pSubNode = pContext->pCurrentNode;
			pSubNode->SetName(name);
		}
		else
		pSubNode = new CXMLNode(name);

		for(int i = 0 ; atts[i] != NULL ; i += 2)
		pSubNode->SetAttribut(atts[i], atts[i + 1]);

		if(pContext->isRootNode)
		{
			pContext->isRootNode = false;
		}
		else
		{
			pContext->pCurrentNode->PushChild(pSubNode);
			pContext->pCurrentNode = pSubNode;
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		throw CXMLParserException(CXMLParserException::XPEC_EVENTSTARTELEMENTERROR);
	}
}

void CXMLParser::EventEndElement(void* pvContext, const char* name)
{
	try
	{
		SContext* pContext = (SContext*) pvContext;
		pContext->pCurrentNode = pContext->pCurrentNode->GetParent();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		throw CXMLParserException(CXMLParserException::XPEC_EVENTENDELEMENTERROR);
	}
}


CXMLParserException::CXMLParserException(int code) : CException(code)
{}

CXMLParserException::~CXMLParserException() throw()
{}

const char* CXMLParserException::what() const throw()
{
	switch(GetCode())
	{
	case XPEC_PARSEERROR:
		return "CXMLParserException::Parse() error";

	case XPEC_EVENTDATAELEMENTERROR:
		return "CXMLParserException::EventDataElement() error";

	case XPEC_EVENTSTARTELEMENTERROR:
		return "CXMLParserException::EventStartElement() error";

	case XPEC_EVENTENDELEMENTERROR:
		return "CXMLParserException::EventEndElement() error";

	default:
		return "CXMLParserException: Unknown error";
	}
}

