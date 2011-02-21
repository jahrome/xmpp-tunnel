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

#ifndef __CCHANNEL_H__
#define __CCHANNEL_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CStream.h>
#include <xmpp/xep/xibb/handler/CChannelDataHandler.h>
#include <xmpp/xep/xibb/handler/CStreamOpenHandler.h>

using namespace std;

class CChannel : public CObject
{
public:
	CChannel();
	CChannel(const CJid& rRemoteJid, u16 remoteCid, u16 maxStream, u16 blockSize, u32 byteRate);
	
	virtual ~CChannel();

	void Init(const CJid& rRemoteJid, u16 remoteCid, u16 maxStream, u16 blockSize, u32 byteRate);

	const CJid& GetRemoteJid() const;
	u16 GetRemoteCid() const;
	u16 GetMaxStream() const;
	u16 GetBlockSize() const;
	u32 GetByteRate() const;


	CChannelDataHandler* GetChannelDataHandler();
	CStreamOpenHandler* GetStreamOpenHandler();
	
	u16 AddStream(CStream* pStream);

	CStream* GetStreamByLocalSid(u16 localSid);
	CStream* GetStreamByRemoteSid(u16 remoteSid);

	void RemoveStreamByLocalSid(u16 localSid);
	void RemoveStreamByRemoteSid(u16 remoteSid);

private:
	CJid RemoteJid;
	u16 remoteCid;
	u16 blockSize;
	u32 byteRate;
	
	CChannelDataHandler ChannelDataHandler;
	CStreamOpenHandler StreamOpenHandler;
			
	vector<CStream*> StreamList;
};
 
class CChannelException : public CException
{
public:
	enum ChannelExceptionCode
	{
		CEC_CONSTRUCTORERROR,
		CEC_DESTRUCTORERROR,
		CEC_INITERROR,
		CEC_ADDSTREAMERROR,
		CEC_GETSTREAMBYLOCALSIDERROR,
		CEC_GETSTREAMBYREMOTESIDERROR,
		CEC_REMOVESTREAMBYLOCALSIDERROR,
		CEC_REMOVESTREAMBYREMOTESIDERROR,
		CEC_GETLOCALSIDERROR
	};

public:
	CChannelException(int code);
	virtual ~CChannelException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNEL_H__
