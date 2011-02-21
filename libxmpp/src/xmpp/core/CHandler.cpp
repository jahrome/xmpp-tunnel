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

#include <common/CException.h>
#include <common/CObject.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CHandler.h>

using namespace std;

CHandler::CHandler()
{}

CHandler::~CHandler()
{
	try
	{
		SignalDestroy();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
	}
}

void CHandler::AddXMLFilter(CXMLFilter* pXMLFilter)
{
	try
	{
		MutexXMLNodeQueue.Lock();
		XMLFilterList.push_back(pXMLFilter);
		MutexXMLNodeQueue.UnLock();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CHandlerException(CHandlerException::HEC_ADDXMLFILTERERROR);
	}
}

bool CHandler::IsMatching(const CXMLNode* pXMLNode)
{
	try
	{
		// for each filter in XMLFilterList, we check that
		// pXMLNode is matching at least one of root filter
		MutexXMLNodeQueue.Lock();

		for(u32 i = 0 ; i < XMLFilterList.size() ; i++)
		{
			if(XMLFilterList[i]->IsMatching(pXMLNode))
			{
				MutexXMLNodeQueue.UnLock();
				return true;
			}
		}
		
		MutexXMLNodeQueue.UnLock();
		return false;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CHandlerException(CHandlerException::HEC_ISMATCHINGERROR);
	}
}

void CHandler::PushXMLNode(CXMLNode* pXMLNode)
{
	try
	{
		MutexXMLNodeQueue.Lock();
		
		XMLNodeQueue.push(pXMLNode);
		MutexXMLNodeQueue.Signal();
		
		MutexXMLNodeQueue.UnLock();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CHandlerException(CHandlerException::HEC_PUSHXMLNODEERROR);
	}
}

CXMLNode* CHandler::PopXMLNode()
{
	try
	{
		MutexXMLNodeQueue.Lock();
		
		while(XMLNodeQueue.empty())
		{
			if(!MutexXMLNodeQueue.Wait())
			{
				MutexXMLNodeQueue.UnLock();
				return NULL;
			}
		}
		
		CXMLNode* pXMLNode = XMLNodeQueue.front();
		XMLNodeQueue.pop();

		MutexXMLNodeQueue.UnLock();
	
		return pXMLNode;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CHandlerException(CHandlerException::HEC_POPXMLNODEERROR);
	}
}

void CHandler::SignalDestroy()
{
	try
	{
		MutexXMLNodeQueue.Lock();
	
		MutexXMLNodeQueue.SignalDestroy();

		while(XMLNodeQueue.size() > 0)
		{
			delete XMLNodeQueue.front();
			XMLNodeQueue.pop();
		}

		for(u32 i = 0 ; i < XMLFilterList.size() ; i++)
		delete XMLFilterList[i];
		
		XMLFilterList.clear();

		MutexXMLNodeQueue.UnLock();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CHandlerException(CHandlerException::HEC_SIGNALDESTROYERROR);
	}
}

CHandlerException::CHandlerException(int code) : CException(code)
{}

CHandlerException::~CHandlerException() throw()
{}
	
const char* CHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case HEC_CONSTRUCTORERROR:
		return "CHandler::Constructor() error";

	case HEC_DESTRUCTORERROR:
		return "CHandler::Destructor() error";

	case HEC_ADDXMLFILTERERROR:
		return "CHandler::AddSubHandler() error";
			
	case HEC_ISMATCHINGERROR:
		return "CHandler::IsMatching() error";
	
	case HEC_PUSHXMLNODEERROR:
		return "CHandler::PushXMLNode() error";
	
	case HEC_POPXMLNODEERROR:
		return "CHandler::PopXMLNode() error";

	case HEC_SIGNALDESTROYERROR:
		return "CHandler::SignalDestroy() error";	

	default:
		return "CHandler: Unknown error";
	}
}
