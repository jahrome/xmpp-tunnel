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

#ifndef __CSESSIONSHELLDATANODE_H__
#define __CSESSIONSHELLDATANODE_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CSessionShellDataNode : public CXMLNode
{
public:
	CSessionShellDataNode();	
	virtual ~CSessionShellDataNode();
	
	bool IsWindowChanged() const;
	u32 GetColumn() const;
	u32 GetRow() const;
	u32 GetX() const;
	u32 GetY() const;

	void SetColumn(u32 column);
	void SetRow(u32 row);
	void SetX(u32 x);
	void SetY(u32 y);
};
 
class CSessionShellDataNodeException : public CException
{
public:
	enum SessionShellDataNodeExceptionCode
	{
		SSDNEC_CONSTRUCTORERROR
	};

public:
	CSessionShellDataNodeException(int code);
	virtual ~CSessionShellDataNodeException() throw();

	virtual const char* what() const throw();
};

#endif // __CSESSIONSHELLDATANODE_H__
