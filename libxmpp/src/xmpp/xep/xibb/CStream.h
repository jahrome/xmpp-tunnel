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

#ifndef __CSTREAM_H__
#define __CSTREAM_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/handler/CStreamDataHandler.h>

using namespace std;

class CStream : public CObject
{
public:
	CStream();
	CStream(const CJid& rRemoteJid, u16 remoteCid, u16 remoteSid, u16 blockSize, u32 byteRate);

	virtual ~CStream();

	void Init(const CJid& rRemoteJid, u16 remoteCid, u16 remoteSid, u16 blockSize, u32 byteRate);

	const CJid& GetRemoteJid() const;
	u16 GetRemoteCid() const;
	u16 GetRemoteSid() const;
	u16 GetBlockSize() const;
	u32 GetByteRate() const;
	
	CStreamDataHandler* GetStreamDataHandler();
	
private:
	CJid RemoteJid;
	u16 remoteCid;
	u16 remoteSid;
	u16 blockSize;
	u32 byteRate;
	CStreamDataHandler StreamDataHandler;
};
 
class CStreamException : public CException
{
public:
	enum StreamExceptionCode
	{
		SEC_CONSTRUCTORERROR,
		SEC_DESTRUCTORERROR,
		SEC_INITERROR
	};

public:
	CStreamException(int code);
	virtual ~CStreamException() throw();

	virtual const char* what() const throw();
};

#endif // __CSTREAM_H__
