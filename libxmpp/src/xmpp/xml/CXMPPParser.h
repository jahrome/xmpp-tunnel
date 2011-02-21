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

#ifndef __CXMPPPARSER_H__
#define __CXMPPPARSER_H__

#include <expat.h>
#include <queue>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/thread/CMutex.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CXMPPParser : CObject
{
public:
	CXMPPParser();
	virtual ~CXMPPParser();

	void Init();
	void ReInit();
	void Destroy();

	void Write(const CBuffer* pBuffer);
	CXMLNode* GetXMLNode();
	u32 GetNumXMLNode();

protected:
	static void EventDataElement(void* pvThis, const char* name, int len);
	static void EventStartElement(void* pvThis, const char* name, const char** atts);
	static void EventEndElement(void* pvThis, const char* name);

private:
	XML_Parser parser;
	CXMLNode* pCurrentNode;
	CXMLNode* pRootNode;
	CMutex Mutex;
	queue<CXMLNode*> XMLNodeQueue;
};

class CXMPPParserException : public CException
{
public:
	enum XMPPParserExceptionCode
	{
		XPEC_PARSINGERROR,
		XPEC_CREATINGERROR,
		XPEC_FREEINGERROR,
		XPEC_GETSTANZAERROR
	};

public:
	CXMPPParserException(int code);
	virtual ~CXMPPParserException() throw();

	virtual const char* what() const throw();
};

#endif //__CXMPPPARSER_H__
