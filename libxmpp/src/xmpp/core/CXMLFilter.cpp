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

#include <xmpp/core/CXMLFilter.h>

using namespace std;

CXMLFilter::CXMLFilter() : CXMLNode()
{}

CXMLFilter::CXMLFilter(const string& name) : CXMLNode(name)
{}

CXMLFilter::~CXMLFilter()
{}

bool CXMLFilter::IsMatching(const CXMLNode* pXMLNode) const
{
	if(GetName() != pXMLNode->GetName())
	return false;

	for(u32 i = 0 ; i < GetNumAttribut() ; i += 2)
	{
		if(!pXMLNode->IsExistAttribut(GetAttribut(i), GetAttribut(i + 1)))
		return false;
	}

	for(u32 i = 0 ; i < GetNumChild() ; i++)
	{
		string childName = GetChild(i)->GetName();
	
		if(!pXMLNode->IsExistChild(childName))
		return false;
		
		if(!GetChild(i)->IsMatching(pXMLNode->GetChild(childName)))
		return false;
	}

	return true;
}

void CXMLFilter::PushChild(CXMLFilter* pXMLFilter)
{
	try
	{
		CXMLNode::PushChild(pXMLFilter);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLFilterException(CXMLFilterException::XMLFEC_PUSHCHILDERROR);
	}
}
const CXMLFilter* CXMLFilter::GetChild(u32 index) const
{
	try
	{
		return (CXMLFilter*) CXMLNode::GetChild(index);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLFilterException(CXMLFilterException::XMLFEC_GETCHILDERROR);
	}
}


CXMLFilterException::CXMLFilterException(int code) : CException(code)
{}

CXMLFilterException::~CXMLFilterException() throw()
{}
	
const char* CXMLFilterException::what() const throw()
{
	switch(GetCode())
	{
	case XMLFEC_CONSTRUCTORERROR:
		return "CXMLFilter::Constructor() error";

	case XMLFEC_DESTRUCTORERROR:
		return "CXMLFilter::Destructor() error";
			
	case XMLFEC_ISMATCHINGERROR:
		return "CXMLFilter::IsMatching() error";
	
	case XMLFEC_PUSHCHILDERROR:
		return "CXMLFilter::PushChild() error";

	case XMLFEC_GETCHILDERROR:
		return "CXMLFilter::GetChild() error";
	
	default:
		return "CXMLFilter: Unknown error";
	}
}
