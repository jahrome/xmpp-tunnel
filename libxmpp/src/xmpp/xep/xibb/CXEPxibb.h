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

#ifndef __CXEPXIBB_H__
#define __CXEPXIBB_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/thread/CMutex.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CXMPPCore.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CChannelManager.h>
#include <xmpp/xep/xibb/handler/CChannelOpenHandler.h>
#include <xmpp/xep/xibb/handler/CChannelCloseHandler.h>
#include <xmpp/xep/xibb/handler/CStreamCloseHandler.h>
#include <xmpp/xep/xibb/handler/CPresenceHandler.h>

using namespace std;

class CXEPxibb : public CObject
{
public:
	CXEPxibb(u16 MaxRemoteJid = 65535, u16 maxChannel = 65535);
	virtual ~CXEPxibb();

	void Attach(CXMPPCore* pXMPPCore);
	void Detach();

	u16 GetMaxRemoteJid() const;
	u16 GetMaxChannel() const;

	void WaitChannel(CJid* pJid, u16* pLocalCid, u16* pMaxStream, u16* pBlockSize, u32* pByteRate);
	void WaitStream(const CJid& rJid, u16 localCid, u16* pLocalSid, u16* pBlockSize, u32* pByteRate);

	void OpenChannel(const CJid& rJid, u16* pLocalCid, u16 maxStream = 65535, u16 blockSize = 4096, u32 byteRate = 0);
	void OpenStream(const CJid& rJid, u16 localCid, u16* pLocalSid, u16 blockSize = 4096, u32 byteRate = 0);

	void SendChannelData(const CJid& rJid, u16 localCid, CBuffer* pBuffer);
	void SendStreamData(const CJid& rJid, u16 localCid, u16 localSid, CBuffer* pBuffer);

	void ReceiveChannelData(const CJid& rJid, u16 localCid, CBuffer* pBuffer);
	void ReceiveStreamData(const CJid& rJid, u16 localCid, u16 localSid, CBuffer* pBuffer);

	void CloseChannel(const CJid& rJid, u16 localCid);
	void CloseStream(const CJid& rJid, u16 localCid, u16 localSid);

private:
	void AddChannelManager(CChannelManager* pChannelManager);
	CChannelManager* GetChannelManager(const CJid& rJid);
	void RemoveChannelManager(const CJid& rJid);

	static void* OnChannelCloseJob(void* pvThis) throw();
	static void* OnStreamCloseJob(void* pvThis) throw();
	static void* OnPresenceJob(void* pvThis) throw();

private:
	CXMPPCore* pXMPPCore;

	u16 maxChannel;
	
	CThread ThreadOnChannelCloseJob;
	CThread ThreadOnStreamCloseJob;
	CThread ThreadOnPresenceJob;

	vector<CChannelManager*> ChannelManagerList;
	CMutex MutexOnChannelManager;

	CChannelOpenHandler ChannelOpenHandler;
	CChannelCloseHandler ChannelCloseHandler;
	CStreamCloseHandler StreamCloseHandler;
	CPresenceHandler PresenceHandler;
};
 
class CXEPxibbException : public CException
{
public:
	enum XEPxibbExceptionCode
	{
		XEPXEC_CONSTRUCTORERROR,
		XEPXEC_DESTRUCTORERROR,
		XEPXEC_ATTACHERROR,
		XEPXEC_DETACHERROR,
		XEPXEC_WAITCHANNELERROR,
		XEPXEC_OPENCHANNELERROR,
		XEPXEC_SENDCHANNELDATAERROR,
		XEPXEC_RECEIVECHANNELDATAERROR,
		XEPXEC_CLOSECHANNELERROR,
		XEPXEC_WAITSTREAMERROR,
		XEPXEC_OPENSTREAMERROR,
		XEPXEC_SENDSTREAMDATAERROR,
		XEPXEC_RECEIVESTREAMDATAERROR,
		XEPXEC_CLOSESTREAMERROR,
		XEPXEC_ADDCHANNELMANAGERERROR,
		XEPXEC_GETCHANNELMANAGERERROR,
		XEPXEC_REMOVECHANNELMANAGERERROR
	};

public:
	CXEPxibbException(int code);
	virtual ~CXEPxibbException() throw();

	virtual const char* what() const throw();
};

#endif // __CXEPXIBB_H__
