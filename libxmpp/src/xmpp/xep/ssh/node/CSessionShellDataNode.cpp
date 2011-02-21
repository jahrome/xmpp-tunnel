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
#include <sstream>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/xep/ssh/node/CSessionShellDataNode.h>

using namespace std;

CSessionShellDataNode::CSessionShellDataNode()
{
	try
	{
		SetName("ssh:session:shell:data");
		SetNameSpace("http://www.jabber.org/protocol/xmpp-ssh");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CSessionShellDataNodeException(CSessionShellDataNodeException::SSDNEC_CONSTRUCTORERROR);
	}
}
CSessionShellDataNode::~CSessionShellDataNode()
{
}

bool CSessionShellDataNode::IsWindowChanged() const
{
	return IsExistChild("window-size");
}

CObject::u32 CSessionShellDataNode::GetColumn() const
{
	u32 column;
	
	istringstream ColumnConvertor(GetChild("window-size")->GetAttribut("column"));
	ColumnConvertor >> column;

	return column;
}

CObject::u32 CSessionShellDataNode::GetRow() const
{
	u32 row;
	
	istringstream RowConvertor(GetChild("window-size")->GetAttribut("row"));
	RowConvertor >> row;

	return row;
}

CObject::u32 CSessionShellDataNode::GetX() const
{
	u32 xpixel;
	
	istringstream XPixelConvertor(GetChild("window-size")->GetAttribut("xpixel"));
	XPixelConvertor >> xpixel;

	return xpixel;
}

CObject::u32 CSessionShellDataNode::GetY() const
{
	u32 ypixel;
	
	istringstream YPixelConvertor(GetChild("window-size")->GetAttribut("ypixel"));
	YPixelConvertor >> ypixel;

	return ypixel;
}

void CSessionShellDataNode::SetColumn(u32 column)
{	
	CXMLNode* pWindowSizeNode;
	ostringstream ColumnConvertor;
	
	if(!IsExistChild("window-size"))
	{
		pWindowSizeNode = new CXMLNode("window-size");
		PushChild(pWindowSizeNode);
	}
	else
	pWindowSizeNode = GetChild("window-size");

		// we convert cid to a string
		
	ColumnConvertor << column;

	pWindowSizeNode->SetAttribut("column", ColumnConvertor.str());
}

void CSessionShellDataNode::SetRow(u32 row)
{
	CXMLNode* pWindowSizeNode;
	ostringstream RowConvertor;
	
	if(!IsExistChild("window-size"))
	{
		pWindowSizeNode = new CXMLNode("window-size");
		PushChild(pWindowSizeNode);
	}
	else
	pWindowSizeNode = GetChild("window-size");

		// we convert cid to a string
		
	RowConvertor << row;

	pWindowSizeNode->SetAttribut("row", RowConvertor.str());
}

void CSessionShellDataNode::SetX(u32 x)
{
	CXMLNode* pWindowSizeNode;
	ostringstream XPixelConvertor;
	
	if(!IsExistChild("window-size"))
	{
		pWindowSizeNode = new CXMLNode("window-size");
		PushChild(pWindowSizeNode);
	}
	else
	pWindowSizeNode = GetChild("window-size");

		// we convert cid to a string
		
	XPixelConvertor << x;

	pWindowSizeNode->SetAttribut("xpixel", XPixelConvertor.str());
}

void CSessionShellDataNode::SetY(u32 y)
{
	CXMLNode* pWindowSizeNode;
	ostringstream YPixelConvertor;
	
	if(!IsExistChild("window-size"))
	{
		pWindowSizeNode = new CXMLNode("window-size");
		PushChild(pWindowSizeNode);
	}
	else
	pWindowSizeNode = GetChild("window-size");

		// we convert cid to a string
		
	YPixelConvertor << y;

	pWindowSizeNode->SetAttribut("ypixel", YPixelConvertor.str());
}

CSessionShellDataNodeException::CSessionShellDataNodeException(int code) : CException(code)
{}

CSessionShellDataNodeException::~CSessionShellDataNodeException() throw()
{}
	
const char* CSessionShellDataNodeException::what() const throw()
{
	switch(GetCode())
	{
	case SSDNEC_CONSTRUCTORERROR:
		return "CSessionShellDataNode::Constructor() error";

	default:
		return "CSessionShellDataNode: Unknown error";
	}
}
