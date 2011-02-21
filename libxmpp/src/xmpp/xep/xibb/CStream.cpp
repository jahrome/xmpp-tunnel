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
#include <sstream>
#include <string>
#include <vector>
#include <time.h>

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CStream.h>
#include <xmpp/xep/xibb/handler/CStreamDataHandler.h>

using namespace std;

CStream::CStream()
{
}

CStream::CStream(const CJid& rRemoteJid, u16 remoteCid, u16 remoteSid, u16 blockSize, u32 byteRate)
{
	Init(rRemoteJid, remoteCid, remoteSid, blockSize, byteRate);
}

CStream::~CStream()
{
	try
	{
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

void CStream::Init(const CJid& rRemoteJid, u16 remoteCid, u16 remoteSid, u16 blockSize, u32 byteRate)
{
	try
	{
		RemoteJid = rRemoteJid;
		this->remoteCid = remoteCid;
		this->remoteSid = remoteSid;
		this->blockSize = blockSize;
		this->byteRate = byteRate;

		StreamDataHandler.Init(rRemoteJid, remoteCid, remoteSid);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamException(CStreamException::SEC_INITERROR);
	}
}

const CJid& CStream::GetRemoteJid() const
{
	return RemoteJid;
}

CObject::u16 CStream::GetRemoteCid() const
{
	return remoteCid;
}

CObject::u16 CStream::GetRemoteSid() const
{
	return remoteSid;
}

CObject::u16 CStream::GetBlockSize() const
{
	return blockSize;
}

CObject::u32 CStream::GetByteRate() const
{
	return byteRate;
}


CStreamDataHandler* CStream::GetStreamDataHandler()
{
	return &StreamDataHandler;
}

CStreamException::CStreamException(int code) : CException(code)
{}

CStreamException::~CStreamException() throw()
{}
	
const char* CStreamException::what() const throw()
{
	switch(GetCode())
	{
	case SEC_CONSTRUCTORERROR:
		return "CStream::Constructor() error";
		
	case SEC_DESTRUCTORERROR:
		return "CStream::Destructor() error";
		
	case SEC_INITERROR:
		return "CStream::Init() error";
				
	default:
		return "CStream: Unknown error";
	}
}
