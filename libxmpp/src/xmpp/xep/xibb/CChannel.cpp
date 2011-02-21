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
#include <common/thread/CMutex.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CChannel.h>
#include <xmpp/xep/xibb/CStream.h>

using namespace std;

CChannel::CChannel()
{
}

CChannel::CChannel(const CJid& rRemoteJid, u16 remoteCid, u16 maxStream, u16 blockSize, u32 byteRate)
{
	try
	{
		Init(rRemoteJid, remoteCid, maxStream, blockSize, byteRate);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

CChannel::~CChannel()
{
	try
	{
		for(u16 i = 0 ; i < StreamList.size() ; i++)
		{
			if(StreamList[i] != NULL)
			delete StreamList[i];
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_DESTRUCTORERROR);
	}
}

void CChannel::Init(const CJid& rRemoteJid, u16 remoteCid, u16 maxStream, u16 blockSize, u32 byteRate)
{
	try
	{
		RemoteJid = rRemoteJid;
		this->remoteCid = remoteCid;
		StreamList.resize(maxStream);
		this->blockSize = blockSize;
		this->byteRate = byteRate;
		
		for(u16 i = 0 ; i < StreamList.size() ; i++)
		StreamList[i] = NULL;
		
		ChannelDataHandler.Init(rRemoteJid, remoteCid);
		StreamOpenHandler.Init(rRemoteJid, remoteCid);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_INITERROR);
	}
}

const CJid& CChannel::GetRemoteJid() const
{
	return RemoteJid;
}

CObject::u16 CChannel::GetRemoteCid() const
{
	return remoteCid;
}

CObject::u16 CChannel::GetMaxStream() const
{
	return StreamList.size();
}

CObject::u16 CChannel::GetBlockSize() const
{
	return blockSize;
}

CObject::u32 CChannel::GetByteRate() const
{
	return byteRate;
}

CChannelDataHandler* CChannel::GetChannelDataHandler()
{
	return &ChannelDataHandler;
}

CStreamOpenHandler* CChannel::GetStreamOpenHandler()
{
	return &StreamOpenHandler;
}
	
CStream* CChannel::GetStreamByLocalSid(u16 localSid)
{
	try
	{
		return StreamList[localSid];
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_GETSTREAMBYLOCALSIDERROR);
	}
}

CStream* CChannel::GetStreamByRemoteSid(u16 remoteSid)
{
	try
	{
		for(u16 i = 0 ; i < StreamList.size() ; i++)
		{
			CStream* pStream = StreamList[i];

			if(pStream != NULL && pStream->GetRemoteSid() == remoteSid)
			return pStream;
		}
		
		return NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_GETSTREAMBYREMOTESIDERROR);
	}
}

CObject::u16 CChannel::AddStream(CStream* pStream)
{
	try
	{
		for(u16 i = 0 ; i < StreamList.size() ; i++)
		{
			if(StreamList[i] == NULL)
			{
				StreamList[i] = pStream;
				return i;
			}
		}

		throw CChannelException(CChannelException::CEC_ADDSTREAMERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_ADDSTREAMERROR);
	}
}

void CChannel::RemoveStreamByLocalSid(u16 localSid)
{
	try
	{
		if(StreamList[localSid] == NULL)
		return;
		
		delete StreamList[localSid];
		StreamList[localSid] = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_REMOVESTREAMBYLOCALSIDERROR);
	}
}

void CChannel::RemoveStreamByRemoteSid(u16 remoteSid)
{
	try
	{
		for(u16 i = 0 ; i < StreamList.size() ; i++)
		{
			if(StreamList[i] != NULL)
			{
				if(StreamList[i]->GetRemoteSid() == remoteSid)
				{
					delete StreamList[i];
					StreamList[i] = NULL;
					return;
				}
			}
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelException(CChannelException::CEC_GETSTREAMBYREMOTESIDERROR);
	}
}

CChannelException::CChannelException(int code) : CException(code)
{}

CChannelException::~CChannelException() throw()
{}
	
const char* CChannelException::what() const throw()
{
	switch(GetCode())
	{
	case CEC_CONSTRUCTORERROR:
		return "CChannel::Constructor() error";
		
	case CEC_DESTRUCTORERROR:
		return "CChannel::Destructor() error";
		
	case CEC_INITERROR:
		return "CChannel::Init() error";
		
	case CEC_ADDSTREAMERROR:
		return "CChannel::AddStream() error";

	case CEC_GETSTREAMBYLOCALSIDERROR:
		return "CChannel::GetStreamByLocalSid() error";

	case CEC_GETSTREAMBYREMOTESIDERROR:
		return "CChannel::GetStreamByRemoteSid() error";

	case CEC_REMOVESTREAMBYLOCALSIDERROR:
		return "CChannel::RemoveStreamByLocalSid() error";
		
	case CEC_REMOVESTREAMBYREMOTESIDERROR:
		return "CChannel::RemoveStreamByRemoteSid() error";
		
	default:
		return "CChannel: Unknown error";
	}
}
