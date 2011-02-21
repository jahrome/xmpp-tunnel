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

#ifndef __CXMLPARSER_H__
#define __CXMLPARSER_H__

#include <pthread.h>
#include <string>
#include <vector>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CXMLParser : public CObject
{
private:
	struct SContext
	{
		CXMLNode* pCurrentNode;
		bool isRootNode;
	};

public:
	CXMLParser();
	virtual ~CXMLParser();

	static void Parse(CBuffer* pBuffer, CXMLNode* pXMLNode);
	
protected:
	static void EventDataElement(void* pvContext, const char* name, int len);
	static void EventStartElement(void* pvContext, const char* name, const char** atts);
	static void EventEndElement(void* pvContext, const char* name);
};

class CXMLParserException : public CException
{
public:
	enum XMLParserExceptionCode
	{
		XPEC_PARSEERROR,
		XPEC_EVENTDATAELEMENTERROR,
		XPEC_EVENTSTARTELEMENTERROR,
		XPEC_EVENTENDELEMENTERROR
	};

public:
	CXMLParserException(int code);
	virtual ~CXMLParserException() throw();

	virtual const char* what() const throw();
};

#endif //__CXMLPARSER_H__
