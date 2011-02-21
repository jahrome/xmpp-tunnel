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
 
#ifndef __CHANDLER_H__
#define __CHANDLER_H__

#include <queue>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/thread/CMutex.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CXMLFilter.h>


class CHandler : public CObject
{
public:
	CHandler();
	virtual ~CHandler();
		
	void AddXMLFilter(CXMLFilter* pXMLFilter);	
	bool IsMatching(const CXMLNode* pXMLNode);
	
	void PushXMLNode(CXMLNode* pXMLNode);
	CXMLNode* PopXMLNode();
	void SignalDestroy();

private:
	void Destroy();
	
private:
	vector<CXMLFilter*> XMLFilterList;

	queue<CXMLNode*> XMLNodeQueue;
	CMutex MutexXMLNodeQueue;
};

class CHandlerException : public CException
{
public:
	enum HandlerExceptionCode
	{
		HEC_CONSTRUCTORERROR,
		HEC_DESTRUCTORERROR,
		HEC_ADDXMLFILTERERROR,
		HEC_ISMATCHINGERROR,
		HEC_PUSHXMLNODEERROR,
		HEC_POPXMLNODEERROR,
		HEC_SIGNALDESTROYERROR
	};

public:
	CHandlerException(int code);
	virtual ~CHandlerException() throw();

	virtual const char* what() const throw();
};

#endif //__CHANDLER_H__
