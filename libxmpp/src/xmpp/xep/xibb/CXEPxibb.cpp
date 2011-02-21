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
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/thread/CMutex.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/iq/set/CIQSetStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/stanza/presence/CPresenceStanza.h>
#include <xmpp/xep/xibb/CChannel.h>
#include <xmpp/xep/xibb/CChannelManager.h>
#include <xmpp/xep/xibb/CXEPxibb.h>
#include <xmpp/xep/xibb/handler/CChannelOpenHandler.h>
#include <xmpp/xep/xibb/handler/CChannelCloseHandler.h>
#include <xmpp/xep/xibb/handler/CStreamCloseHandler.h>
#include <xmpp/xep/xibb/handler/CPresenceHandler.h>
#include <xmpp/xep/xibb/stanza/CChannelCloseStanza.h>
#include <xmpp/xep/xibb/stanza/CChannelDataStanza.h>
#include <xmpp/xep/xibb/stanza/CChannelOpenStanza.h>
#include <xmpp/xep/xibb/stanza/CStreamCloseStanza.h>
#include <xmpp/xep/xibb/stanza/CStreamDataStanza.h>
#include <xmpp/xep/xibb/stanza/CStreamOpenStanza.h>

using namespace std;

CXEPxibb::CXEPxibb(u16 maxRemoteJid, u16 maxChannel)
{
	try
	{
		pXMPPCore = NULL;
		ChannelManagerList.resize(maxRemoteJid);
		this->maxChannel = maxChannel;
		
		for(u16 i = 0 ; i < maxRemoteJid ; i++)
		ChannelManagerList[i] = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_CONSTRUCTORERROR);
	}
}

CXEPxibb::~CXEPxibb()
{
	try
	{
		if(pXMPPCore != NULL)
		Detach();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

void CXEPxibb::Attach(CXMPPCore* pXMPPCore)
{
	try
	{
		this->pXMPPCore = pXMPPCore;
		pXMPPCore->RequestHandler(&ChannelOpenHandler);
		pXMPPCore->RequestHandler(&ChannelCloseHandler);
		pXMPPCore->RequestHandler(&StreamCloseHandler);
		pXMPPCore->RequestHandler(&PresenceHandler);

		ThreadOnChannelCloseJob.Run(OnChannelCloseJob, this);
		ThreadOnStreamCloseJob.Run(OnStreamCloseJob, this);
		ThreadOnPresenceJob.Run(OnPresenceJob, this);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_ATTACHERROR);
	}
}

void CXEPxibb::Detach()
{
	try
	{
		if(pXMPPCore == NULL)
		return;
	
		pXMPPCore->CommitHandler(&ChannelOpenHandler);
		pXMPPCore->CommitHandler(&ChannelCloseHandler);
		pXMPPCore->CommitHandler(&StreamCloseHandler);
		pXMPPCore->CommitHandler(&PresenceHandler);
	
		ThreadOnChannelCloseJob.Wait();
		ThreadOnStreamCloseJob.Wait();
		ThreadOnPresenceJob.Wait();
	
		for(u16 i = 0 ; i < ChannelManagerList.size() ; i++)
		{
			CChannelManager* pChannelManager = ChannelManagerList[i];
			
			if(pChannelManager != NULL)
			{
				for(u16 j = 0 ; j < pChannelManager->GetMaxChannel() ; j++)
				{
					CChannel* pChannel = pChannelManager->GetChannelByLocalCid(j);

					if(pChannel != NULL)
					{
						pXMPPCore->CommitHandler(pChannel->GetStreamOpenHandler());
						pXMPPCore->CommitHandler(pChannel->GetChannelDataHandler());
						
						for(u16 k = 0 ; k < pChannel->GetMaxStream() ; k++)
						{
							CStream* pStream = pChannel->GetStreamByLocalSid(k);
								
							if(pStream != NULL)
							{
								pXMPPCore->CommitHandler(pStream->GetStreamDataHandler());
								pChannel->RemoveStreamByLocalSid(k);
							}
						}

						pChannelManager->RemoveChannelByLocalCid(j);
					}	
				}
				
				delete pChannelManager;
				ChannelManagerList[i] = NULL;
			}
		}
	
		pXMPPCore = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_DETACHERROR);
	}
}

CObject::u16 CXEPxibb::GetMaxRemoteJid() const
{
	return ChannelManagerList.size();
}

CObject::u16 CXEPxibb::GetMaxChannel() const
{
	return maxChannel;
}


void CXEPxibb::WaitChannel(CJid* pJid, u16* pLocalCid, u16* pMaxStream, u16* pBlockSize, u32* pByteRate)
{
	// we receive a channel open stanza
	CChannelOpenStanza ChannelOpenStanza;

	if(!pXMPPCore->Receive(&ChannelOpenHandler, &ChannelOpenStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITCHANNELERROR);

	// we are looking for if it already exists or building it otherwise
	MutexOnChannelManager.Lock();
		
	try
	{
		CChannelManager* pChannelManager = GetChannelManager(ChannelOpenStanza.GetFrom());
		
		*pMaxStream = ChannelOpenStanza.GetMaxStream();
		*pBlockSize = ChannelOpenStanza.GetBlockSize();
		*pByteRate = ChannelOpenStanza.GetByteRate();
		
		if(pChannelManager == NULL)
		{
			pChannelManager = new CChannelManager(ChannelOpenStanza.GetFrom(), maxChannel);
			AddChannelManager(pChannelManager);
		}
		
		// we build the associate channel
		CChannel* pChannel = new CChannel(ChannelOpenStanza.GetFrom(),
											ChannelOpenStanza.GetChannelId(),
											*pMaxStream,
											*pBlockSize,
											*pByteRate);

		// we add it
		u16 localCid = pChannelManager->AddChannel(pChannel);
	
		pXMPPCore->RequestHandler(pChannel->GetChannelDataHandler());
		pXMPPCore->RequestHandler(pChannel->GetStreamOpenHandler());

		*pJid = ChannelOpenStanza.GetFrom();
		*pLocalCid = localCid;
	}

	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITCHANNELERROR);
	}
	
	MutexOnChannelManager.UnLock();

	// we send the iq response
	CIQResultStanza IQResultStanza;

	IQResultStanza.SetTo(ChannelOpenStanza.GetFrom());
	IQResultStanza.SetId(ChannelOpenStanza.GetId());

	if(!pXMPPCore->Send(&IQResultStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITCHANNELERROR);		
}

void CXEPxibb::WaitStream(const CJid& rJid, u16 localCid, u16* pLocalSid, u16* pBlockSize, u32* pByteRate)
{
	CChannelManager* pChannelManager;
	CStreamOpenHandler* pStreamOpenHandler;
	CChannel* pChannel;
	CStream* pStream;
	
	MutexOnChannelManager.Lock();

	try
	{		
		// we are looking for the channelmanager associate to the Jid 
		pChannelManager = GetChannelManager(rJid);
		
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITSTREAMERROR);
		
		// we are looking for the channel associate to the localCid 
		pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITSTREAMERROR);

		pStreamOpenHandler = pChannel->GetStreamOpenHandler();
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITSTREAMERROR);
	}
	
	MutexOnChannelManager.UnLock();

	// we receive a stream open stanza
	CStreamOpenStanza StreamOpenStanza;
		
	if(!pXMPPCore->Receive(pStreamOpenHandler, &StreamOpenStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITSTREAMERROR);

	MutexOnChannelManager.Lock();

	try
	{
		*pBlockSize = StreamOpenStanza.GetBlockSize();
		*pByteRate = StreamOpenStanza.GetByteRate();

		pStream = new CStream(rJid, pChannel->GetRemoteCid(), StreamOpenStanza.GetStreamId(), *pBlockSize, *pByteRate);
		u16 localSid = pChannel->AddStream(pStream);

		pXMPPCore->RequestHandler(pStream->GetStreamDataHandler());

		*pLocalSid = localSid;
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITSTREAMERROR);
	}

	MutexOnChannelManager.UnLock();

	// we send the iq response
	CIQResultStanza IQResultStanza;

	IQResultStanza.SetTo(StreamOpenStanza.GetFrom());
	IQResultStanza.SetId(StreamOpenStanza.GetId());

	if(!pXMPPCore->Send(&IQResultStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_WAITSTREAMERROR);		
}

void CXEPxibb::OpenChannel(const CJid& rJid, u16* pLocalCid, u16 maxStream, u16 blockSize, u32 byteRate)
{
	CChannelManager* pChannelManager;
	CChannel* pChannel;
	u16 localCid;
	
	MutexOnChannelManager.Lock();

	try
	{		
		// we are looking for the channelmanager associate to the Jid 		
		pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		{
			pChannelManager = new CChannelManager(rJid, maxChannel);
			AddChannelManager(pChannelManager);
		}
		
		// we build the associate channel
		pChannel = new CChannel();

		// we add it
		localCid = pChannelManager->AddChannel(pChannel);
		pChannel->Init(rJid, localCid, maxStream, blockSize, byteRate);
	
		pXMPPCore->RequestHandler(pChannel->GetChannelDataHandler());
		pXMPPCore->RequestHandler(pChannel->GetStreamOpenHandler());

		*pLocalCid = localCid;
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}

	MutexOnChannelManager.UnLock();

	// we build the channel:open iqstanza
	string id;
	CHandler IQHandler;
	CXMLFilter* pXMLFilter;
	CIQStanza IQStanza;
	CChannelOpenStanza ChannelOpenStanza;

	pXMPPCore->GenerateId(id);

	try
	{
		ChannelOpenStanza.Init(rJid, localCid, maxStream, blockSize, byteRate, id);				
		
		// we build the handler associate to the iqstanza response
		pXMLFilter = new CXMLFilter("iq");
		pXMLFilter->SetAttribut("from", rJid.GetFull());
		pXMLFilter->SetAttribut("id", id);			
		IQHandler.AddXMLFilter(pXMLFilter);
	}
	
	catch(exception& e)
	{
		pXMPPCore->RemoveId(id);
		
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}

	pXMPPCore->RequestHandler(&IQHandler);

	try
	{
		// we send the channel:open iqstanza
		if(!pXMPPCore->Send(&ChannelOpenStanza))
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);

		// we receive the iq result
		if(!pXMPPCore->Receive(&IQHandler, &IQStanza))
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);

		if(IQStanza.GetKindOf() != CIQStanza::SIQKO_RESULT)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}
	
	catch(exception& e)
	{
		pXMPPCore->CommitHandler(&IQHandler);
		pXMPPCore->RemoveId(id);
		
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}

	pXMPPCore->CommitHandler(&IQHandler);
	pXMPPCore->RemoveId(id);

}

void CXEPxibb::OpenStream(const CJid& rJid, u16 localCid, u16* pLocalSid, u16 blockSize, u32 byteRate)
{
	u16 localSid;
	
	MutexOnChannelManager.Lock();

	try
	{		
		// we are looking for the channelmanager associate to the Jid 		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENSTREAMERROR);
		
		// we are looking for the channel associate to the localCid
		CChannel* pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENSTREAMERROR);

		// we build and add the new stream
		CStream* pStream = new CStream();
		localSid = pChannel->AddStream(pStream);
		pStream->Init(rJid, pChannel->GetRemoteCid(), localSid, blockSize, byteRate);

		pXMPPCore->RequestHandler(pStream->GetStreamDataHandler());
		
		*pLocalSid = localSid;
	}

	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}
	
	MutexOnChannelManager.UnLock();

	// we build the stream:open iqstanza
	string id;
	CHandler IQHandler;
	CIQStanza IQStanza;

	CXMLFilter* pXMLFilter;
	CStreamOpenStanza StreamOpenStanza;
	pXMPPCore->GenerateId(id);

	try
	{
		StreamOpenStanza.Init(rJid, localCid, localSid, blockSize, byteRate, id);				
	
		// we build the handler associate to the iqstanza response
		pXMLFilter = new CXMLFilter("iq");
		pXMLFilter->SetAttribut("from", rJid.GetFull());
		pXMLFilter->SetAttribut("id", id);			
		IQHandler.AddXMLFilter(pXMLFilter);
	}

	catch(exception& e)
	{
		pXMPPCore->RemoveId(id);
		
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}

	pXMPPCore->RequestHandler(&IQHandler);

	try
	{
		// we send the stream:open iqstanza
		if(!pXMPPCore->Send(&StreamOpenStanza))
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENSTREAMERROR);

		// we receive the iq result
		if(!pXMPPCore->Receive(&IQHandler, &IQStanza))
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENSTREAMERROR);

		if(IQStanza.GetKindOf() != CIQStanza::SIQKO_RESULT)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENSTREAMERROR);
	}
	
	catch(exception& e)
	{
		pXMPPCore->CommitHandler(&IQHandler);
		pXMPPCore->RemoveId(id);

		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_OPENCHANNELERROR);
	}

	pXMPPCore->CommitHandler(&IQHandler);
	pXMPPCore->RemoveId(id);
}

void CXEPxibb::SendChannelData(const CJid& rJid, u16 localCid, CBuffer* pBuffer)
{
	u16 remoteCid;
	MutexOnChannelManager.Lock();

	try
	{
		// we are looking for the channelmanager associate to the Jid 
		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDCHANNELDATAERROR);
		
		// we are looking for the channel associate to the localCid
		CChannel* pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDCHANNELDATAERROR);
		
		remoteCid = pChannel->GetRemoteCid();
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDCHANNELDATAERROR);
	}
		
	MutexOnChannelManager.UnLock();
	
	CChannelDataStanza ChannelDataStanza(rJid, remoteCid);
	
	CXMLNode* pData = ChannelDataStanza.GetChild("channel-data");
	
	string data;
	CBase64 Base64;
	
	Base64.To64(pBuffer, data);
	pData->SetData(data.c_str(), data.size());

	if(!pXMPPCore->Send(&ChannelDataStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDCHANNELDATAERROR);
}

void CXEPxibb::SendStreamData(const CJid& rJid, u16 localCid, u16 localSid, CBuffer* pBuffer)
{
	u16 remoteCid;
	u16 remoteSid;
	MutexOnChannelManager.Lock();

	try
	{
		// we are looking for the channelmanager associate to the Jid 
		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDSTREAMDATAERROR);
		
		// we are looking for the channel associate to the localCid
		CChannel* pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDSTREAMDATAERROR);
				
		remoteCid = pChannel->GetRemoteCid();

		// we are looking for the stream associate to the localSid
		CStream* pStream = pChannel->GetStreamByLocalSid(localSid);

		if(pStream == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDSTREAMDATAERROR);

		remoteSid = pStream->GetRemoteSid();
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDSTREAMDATAERROR);
	}
	
	MutexOnChannelManager.UnLock();

	CStreamDataStanza StreamDataStanza(rJid, remoteCid, remoteSid);

	CXMLNode* pData = StreamDataStanza.GetChild("stream-data");
	
	string data;
	CBase64 Base64;
	
	Base64.To64(pBuffer, data);
	pData->SetData(data.c_str(), data.size());

	if(!pXMPPCore->Send(&StreamDataStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_SENDSTREAMDATAERROR);
}

void CXEPxibb::ReceiveChannelData(const CJid& rJid, u16 localCid, CBuffer* pBuffer)
{
	CChannelDataHandler* pChannelDataHandler;
	
	MutexOnChannelManager.Lock();

	try
	{
		// we are looking for the channelmanager associate to the Jid 
		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVECHANNELDATAERROR);
		
		// we are looking for the channel associate to the localCid
		CChannel* pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVECHANNELDATAERROR);

		pChannelDataHandler = pChannel->GetChannelDataHandler();

	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVECHANNELDATAERROR);
	}

	MutexOnChannelManager.UnLock();

	CChannelDataStanza ChannelDataStanza;

	if(!pXMPPCore->Receive(pChannelDataHandler, &ChannelDataStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVECHANNELDATAERROR);
	
	CXMLNode* pData = ChannelDataStanza.GetChild("channel-data");

	CBase64 Base64;		
	Base64.From64(pData->GetData(), pBuffer);
}

void CXEPxibb::ReceiveStreamData(const CJid& rJid, u16 localCid, u16 localSid, CBuffer* pBuffer)
{
	CStreamDataHandler* pStreamDataHandler;
	MutexOnChannelManager.Lock();

	try
	{
		// we are looking for the channelmanager associate to the Jid 		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVESTREAMDATAERROR);
		
		// we are looking for the channel associate to the localCid
		CChannel* pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVESTREAMDATAERROR);

		// we are looking for the stream associate to the localSid
		CStream* pStream = pChannel->GetStreamByLocalSid(localSid);

		if(pStream == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVESTREAMDATAERROR);

		pStreamDataHandler = pStream->GetStreamDataHandler();
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVESTREAMDATAERROR);
	}

	MutexOnChannelManager.UnLock();

	CStreamDataStanza StreamDataStanza;

	if(!pXMPPCore->Receive(pStreamDataHandler, &StreamDataStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_RECEIVESTREAMDATAERROR);
	
	CXMLNode* pData = StreamDataStanza.GetChild("stream-data");

	CBase64 Base64;		
	Base64.From64(pData->GetData(), pBuffer);
}

void CXEPxibb::CloseChannel(const CJid& rJid, u16 localCid)
{
	CChannel* pChannel;
	u16 remoteCid;

	MutexOnChannelManager.Lock();

	try
	{
		// we are looking for the channelmanager associate to the Jid 
		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSECHANNELERROR);
		
		// we are looking for the channel associate to the localCid
		pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSECHANNELERROR);

		pXMPPCore->CommitHandler(pChannel->GetStreamOpenHandler());
		pXMPPCore->CommitHandler(pChannel->GetChannelDataHandler());
		
		for(u16 i = 0 ; i < pChannel->GetMaxStream() ; i++)
		{
			CStream* pStream = pChannel->GetStreamByLocalSid(i);
				
			if(pStream != NULL)
			{
				pXMPPCore->CommitHandler(pStream->GetStreamDataHandler());
				pChannel->RemoveStreamByLocalSid(i);
			}
		}

		remoteCid = pChannel->GetRemoteCid();
		pChannelManager->RemoveChannelByLocalCid(localCid);
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		return;
	}

	MutexOnChannelManager.UnLock();

	// we build the iq request
	string id;
	pXMPPCore->GenerateId(id);
	
	try
	{

		CChannelCloseStanza ChannelCloseStanza(rJid, remoteCid, id);

		// we build the handler associate to the iq request
		CIQResultStanza IQResultStanza;
		CHandler IQResultHandler;

		CXMLFilter* pXMLFilter = new CXMLFilter("iq");
		pXMLFilter->SetAttribut("from", rJid.GetFull());
		pXMLFilter->SetAttribut("id", id);

		IQResultHandler.AddXMLFilter(pXMLFilter);
		
		pXMPPCore->RequestHandler(&IQResultHandler);

		// we send the iq request
		if(!pXMPPCore->Send(&ChannelCloseStanza))
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSECHANNELERROR);

		// we receive the iq result
		if(!pXMPPCore->Receive(&IQResultHandler, &IQResultStanza))
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSECHANNELERROR);

		pXMPPCore->CommitHandler(&IQResultHandler);
	}
	
	catch(exception& e)
	{
		pXMPPCore->RemoveId(id);
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSECHANNELERROR);
	}

	pXMPPCore->RemoveId(id);
}

void CXEPxibb::CloseStream(const CJid& rJid, u16 localCid, u16 localSid)
{
	u16 remoteCid;
	u16 remoteSid;
	
	MutexOnChannelManager.Lock();

	try
	{
		// we are looking for the channelmanager associate to the Jid 		
		CChannelManager* pChannelManager = GetChannelManager(rJid);
				
		if(pChannelManager == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSESTREAMERROR);
		
		// we are looking for the channel associate to the localCid
		CChannel* pChannel = pChannelManager->GetChannelByLocalCid(localCid);

		if(pChannel == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSESTREAMERROR);

		remoteCid = pChannel->GetRemoteCid();

		// we are looking for the stream associate to the localSid
		CStream* pStream = pChannel->GetStreamByLocalSid(localSid);

		if(pStream == NULL)
		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSESTREAMERROR);

		remoteSid = pStream->GetRemoteSid();

		pXMPPCore->CommitHandler(pStream->GetStreamDataHandler());
		pChannel->RemoveStreamByLocalSid(localSid);
	}
	
	catch(exception& e)
	{
		MutexOnChannelManager.UnLock();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSESTREAMERROR);
	}

	MutexOnChannelManager.UnLock();

	// we build the iq request
	string id;
	pXMPPCore->GenerateId(id);
	
	CStreamCloseStanza StreamCloseStanza(rJid, remoteCid, remoteSid, id);

	// we build the handler associate to the iq request
	CIQResultStanza IQResultStanza;
	CHandler IQResultHandler;

	CXMLFilter* pXMLFilter = new CXMLFilter("iq");
	pXMLFilter->SetAttribut("from", rJid.GetFull());
	pXMLFilter->SetAttribut("id", id);

	IQResultHandler.AddXMLFilter(pXMLFilter);
	
	pXMPPCore->RequestHandler(&IQResultHandler);

	// we send the iq request
	if(!pXMPPCore->Send(&StreamCloseStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSESTREAMERROR);

	// we receive the iq result
	if(!pXMPPCore->Receive(&IQResultHandler, &IQResultStanza))
	throw CXEPxibbException(CXEPxibbException::XEPXEC_CLOSESTREAMERROR);

	pXMPPCore->CommitHandler(&IQResultHandler);
	pXMPPCore->RemoveId(id);
}

void CXEPxibb::AddChannelManager(CChannelManager* pChannelManager)
{
	try
	{
		for(u16 i = 0 ; i < ChannelManagerList.size() ; i++)
		{
			if(ChannelManagerList[i] == NULL)
			{
				ChannelManagerList[i] = pChannelManager;
				return;
			}
		}
		
		throw CXEPxibbException(CXEPxibbException::XEPXEC_ADDCHANNELMANAGERERROR);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_ADDCHANNELMANAGERERROR);
	}
}

CChannelManager* CXEPxibb::GetChannelManager(const CJid& rJid)
{
	try
	{
		for(u16 i = 0 ; i < ChannelManagerList.size() ; i++)
		{
			if(ChannelManagerList[i] != NULL)
			{
				if(ChannelManagerList[i]->GetRemoteJid() == rJid)
				return ChannelManagerList[i];
			}
		}
		
		return NULL;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPxibbException(CXEPxibbException::XEPXEC_GETCHANNELMANAGERERROR);
	}
}

void CXEPxibb::RemoveChannelManager(const CJid& rJid)
{
	try
	{
		for(u16 i = 0 ; i < ChannelManagerList.size() ; i++)
		{
			if(ChannelManagerList[i] != NULL)
			{
				if(ChannelManagerList[i]->GetRemoteJid() == rJid)
				{
					delete ChannelManagerList[i];
					ChannelManagerList[i] = NULL;
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

		throw CXEPxibbException(CXEPxibbException::XEPXEC_REMOVECHANNELMANAGERERROR);
	}
}


void* CXEPxibb::OnChannelCloseJob(void* pvThis) throw()
{
	CXEPxibb* pXEPxibb = (CXEPxibb*) pvThis;
	CChannelCloseHandler* pChannelCloseHandler = &(pXEPxibb->ChannelCloseHandler);
	CXMPPCore* pXMPPCore = pXEPxibb->pXMPPCore;

	CChannelCloseStanza ChannelCloseStanza;

	while(pXMPPCore->Receive(pChannelCloseHandler, &ChannelCloseStanza))
	{
		pXEPxibb->MutexOnChannelManager.Lock();
		
		try
		{
			CChannelManager* pChannelManager = pXEPxibb->GetChannelManager(ChannelCloseStanza.GetRemoteJid());

			if(pChannelManager != NULL)
			{
				CChannel* pChannel = pChannelManager->GetChannelByRemoteCid(ChannelCloseStanza.GetChannelId());

				if(pChannel != NULL)
				{
					pXMPPCore->CommitHandler(pChannel->GetStreamOpenHandler());
					pXMPPCore->CommitHandler(pChannel->GetChannelDataHandler());
				
					for(u16 i = 0 ; i < pChannel->GetMaxStream() ; i++)
					{
						CStream* pStream = pChannel->GetStreamByLocalSid(i);
						
						if(pStream != NULL)
						{
							pXMPPCore->CommitHandler(pStream->GetStreamDataHandler());
							pChannel->RemoveStreamByLocalSid(i);
						}
					}
				}
				
				pChannelManager->RemoveChannelByRemoteCid(ChannelCloseStanza.GetChannelId());
			}
		}
		
		catch(exception& e)
		{
			#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		}
		
		pXEPxibb->MutexOnChannelManager.UnLock();

		CIQResultStanza IQResultStanza;		
		IQResultStanza.SetTo(ChannelCloseStanza.GetRemoteJid());
		IQResultStanza.SetId(ChannelCloseStanza.GetId());
		 
		if(!pXMPPCore->Send(&IQResultStanza))
		return NULL;
	}
	
	return NULL;
}

void* CXEPxibb::OnStreamCloseJob(void* pvThis) throw()
{
	CXEPxibb* pXEPxibb = (CXEPxibb*) pvThis;
	CStreamCloseHandler* pStreamCloseHandler = &(pXEPxibb->StreamCloseHandler);
	CXMPPCore* pXMPPCore = pXEPxibb->pXMPPCore;

	CStreamCloseStanza StreamCloseStanza;

	while(pXMPPCore->Receive(pStreamCloseHandler, &StreamCloseStanza))
	{
		pXEPxibb->MutexOnChannelManager.Lock();
		
		try
		{
			CChannelManager* pChannelManager = pXEPxibb->GetChannelManager(StreamCloseStanza.GetRemoteJid());

			if(pChannelManager != NULL)
			{
				CChannel* pChannel = pChannelManager->GetChannelByRemoteCid(StreamCloseStanza.GetChannelId());

				if(pChannel != NULL)
				{
					CStream* pStream = pChannel->GetStreamByRemoteSid(StreamCloseStanza.GetStreamId());
						
					if(pStream != NULL)
					{
						pXMPPCore->CommitHandler(pStream->GetStreamDataHandler());
						pChannel->RemoveStreamByRemoteSid(StreamCloseStanza.GetStreamId());
					}
				}
			}
		}
		
		catch(exception& e)
		{
			#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		}

		pXEPxibb->MutexOnChannelManager.UnLock();

		CIQResultStanza IQResultStanza;		
		IQResultStanza.SetTo(StreamCloseStanza.GetRemoteJid());
		IQResultStanza.SetId(StreamCloseStanza.GetId());
		 
		if(!pXMPPCore->Send(&IQResultStanza))
		return NULL;
	}
	
	return NULL;
}

void* CXEPxibb::OnPresenceJob(void* pvThis) throw()
{
	CXEPxibb* pXEPxibb = (CXEPxibb*) pvThis;
	CPresenceHandler* pPresenceHandler = &(pXEPxibb->PresenceHandler);
	CXMPPCore* pXMPPCore = pXEPxibb->pXMPPCore;

	CPresenceStanza PresenceStanza;

	while(pXMPPCore->Receive(pPresenceHandler, &PresenceStanza))
	{
		pXEPxibb->MutexOnChannelManager.Lock();
		
		try
		{
			CChannelManager* pChannelManager = pXEPxibb->GetChannelManager(PresenceStanza.GetFrom());

			if(pChannelManager != NULL)
			{
				for(u16 i = 0 ; i < pChannelManager->GetMaxChannel() ; i++)
				{
					CChannel* pChannel = pChannelManager->GetChannelByLocalCid(i);
					
					if(pChannel != NULL)
					{
						pXMPPCore->CommitHandler(pChannel->GetStreamOpenHandler());
						pXMPPCore->CommitHandler(pChannel->GetChannelDataHandler());
					
						for(u16 j = 0 ; j < pChannel->GetMaxStream() ; j++)
						{
							CStream* pStream = pChannel->GetStreamByLocalSid(j);
							
							if(pStream != NULL)
							{
								pXMPPCore->CommitHandler(pStream->GetStreamDataHandler());
								pChannel->RemoveStreamByLocalSid(j);
							}
						}
						
						pChannelManager->RemoveChannelByLocalCid(i);
					}
				}

				pXEPxibb->RemoveChannelManager(PresenceStanza.GetFrom());
			}
		}
		
		catch(exception& e)
		{
			#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		}
		
		pXEPxibb->MutexOnChannelManager.UnLock();
	}
	
	return NULL;
}


CXEPxibbException::CXEPxibbException(int code) : CException(code)
{}

CXEPxibbException::~CXEPxibbException() throw()
{}
	
const char* CXEPxibbException::what() const throw()
{
	switch(GetCode())
	{
	case XEPXEC_CONSTRUCTORERROR:
		return "CXEPxibb::Constructor() error";
		
	case XEPXEC_DESTRUCTORERROR:
		return "CXEPxibb::Destructor() error";
		
	case XEPXEC_ATTACHERROR:
		return "CXEPxibb::Attach() error";

	case XEPXEC_DETACHERROR:
		return "CXEPxibb::Detach() error";

	case XEPXEC_WAITCHANNELERROR:
		return "CXEPxibb::WaitChannel() error";
	
	case XEPXEC_OPENCHANNELERROR:
		return "CXEPxibb::OpenChannel() error";
	
	case XEPXEC_SENDCHANNELDATAERROR:
		return "CXEPxibb::SendChannelData() error";

	case XEPXEC_RECEIVECHANNELDATAERROR:
		return "CXEPxibb::ReceiveChannelData() error";

	case XEPXEC_CLOSECHANNELERROR:
		return "CXEPxibb::CloseChannel() error";

	case XEPXEC_WAITSTREAMERROR:
		return "CXEPxibb::WaitStream() error";
	
	case XEPXEC_OPENSTREAMERROR:
		return "CXEPxibb::OpenStream() error";
	
	case XEPXEC_SENDSTREAMDATAERROR:
		return "CXEPxibb::SendStreamData() error";

	case XEPXEC_RECEIVESTREAMDATAERROR:
		return "CXEPxibb::ReceiveStreamData() error";

	case XEPXEC_CLOSESTREAMERROR:
		return "CXEPxibb::CloseStream() error";
		
	case XEPXEC_ADDCHANNELMANAGERERROR:
		return "CXEPxibb::AddChannelManager() error";

	case XEPXEC_GETCHANNELMANAGERERROR:
		return "CXEPxibb::GetChannelManager() error";

	case XEPXEC_REMOVECHANNELMANAGERERROR:
		return "CXEPxibb::RemoveChannelManager() error";

	default:
		return "CXEPxibb: Unknown error";
	}
}
