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

#ifndef __CBASE64_H__
#define __CBASE64_H__

#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBase64.h>
#include <common/data/CBuffer.h>

using namespace std;

class CBase64 : public CObject
{
public:
	CBase64();
	~CBase64();

	void To64(CBuffer* pBufferIn, string& strOut);
	void To64(CBuffer* pBufferIn, CBuffer* pBufferOut);
	void From64(const string& strIn, CBuffer* pBufferOut);
	void From64(CBuffer* pBufferOut, CBuffer* pBufferOut);
	
private :
	int GetOffset(char car);
	
private:
	char base64[65];
	int padOffset;
	int badOffset;
};

class CBase64Exception : public CException
{
public:
	enum Base64ExceptionCode
	{
		B64EC_TO64ERROR,
		B64EC_FROM64ERROR,
		B64EC_GETOFFSETERROR
	};

public:
	CBase64Exception(int code);
	virtual ~CBase64Exception() throw();

	virtual const char* what() const throw();
};

#endif // __CBASE64_H__
