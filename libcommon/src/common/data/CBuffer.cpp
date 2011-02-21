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
#include <stdlib.h>
#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include "common/data/CBuffer.h"

using namespace std;

CBuffer::CBuffer()
{
	Init();
}

CBuffer::CBuffer(u32 bufferSize)
{
	Init();
	Create(bufferSize);
}

CBuffer::~CBuffer()
{
	try
	{
		ReInit();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
	}
}
int CBuffer::Create(u32 bufferSize)
{
	ReInit();

	buffer = new u8[bufferSize];
	
	if(buffer == NULL)
	return 0;

	this->bufferSize = bufferSize;

	SetNotEmpty();
	return 1;
}

int CBuffer::Affect(const char str[])
{
	Create(strlen(str));
	return Write(str);
}

int CBuffer::Affect(const string& str)
{
	return Affect(str.c_str());
}

int CBuffer::Affect(const CBuffer* pBuffer)
{

	ReInit();

	if(pBuffer->IsEmpty())
	return 1;
	
	buffer = new u8[pBuffer->GetBufferSize()];

	if(buffer == NULL)
	return 0;

	bufferSize = pBuffer->GetBufferSize();

	for(u32 i = 0 ; i < pBuffer->GetBufferSize() ; i++)
	buffer[i] = pBuffer->GetBuffer()[i];

	SetNotEmpty();
	return 1;
}


int CBuffer::Write(const u8* pData, u32 dataSize)
{
	if(pData == NULL || dataSize == 0)
	return 0;

	if(IsEmpty())
	return 0;

	if(GetWritePos() + dataSize > GetBufferSize())
	return 0;

	for(u32 i = 0 ; i < dataSize ; i++)
	buffer[GetWritePos() + i] = pData[i];

	writePos += dataSize;
	
	return 1;
}

int CBuffer::Write(const CBuffer* pBuffer)
{
	return Write(pBuffer->GetBuffer(), pBuffer->GetBufferSize());
}

int CBuffer::Read(CBuffer* pBuffer)
{
	return Read(pBuffer->GetBuffer(), pBuffer->GetBufferSize());
}

int CBuffer::Write(const string& data)
{
	return Write(data.c_str());
}

int CBuffer::Write(const string* pData)
{
	return Write(pData->c_str());
}

int CBuffer::Read(u8* pData, u32 dataSize)
{
	if(pData == NULL || dataSize == 0)
	return 0;

	if(IsEmpty())
	return 0;

	if(GetReadPos() + dataSize > GetBufferSize())
	return 0;

	for(u32 i = 0 ; i < dataSize ; i++)
	pData[i] = buffer[GetReadPos() + i];

	readPos += dataSize;
	
	return 1;
}

int CBuffer::Write(const char pData[])
{
	return Write((u8*) pData, strlen(pData));
}

int CBuffer::Read(char* pData, u32 dataSize)
{
	return Read((u8*) pData, dataSize);
}


int CBuffer::Write(const char data)
{
	return Write((u8*) &data, sizeof(char));
}

int CBuffer::Read(char* pData)
{
	return Read((u8*) pData, sizeof(char));
}

CObject::u8 CBuffer::GetByte()
{
	u8 data = 0;
	Read(&data, sizeof(u8));

	return data;
}


int CBuffer::Write(const u8 data)
{
	return Write(&data, sizeof(u8));
}

int CBuffer::Read(u8* pData)
{
	return Read(pData, sizeof(u8));
}

int CBuffer::Write(const uInt16 data)
{
	u8 data1 = (u8) ((data >> 8) & 0xFF);
	u8 data2 = (u8) ((data >> 0) & 0xFF);
	 
	return Write(data1) &&  Write(data2);
}

int CBuffer::Read(uInt16* pData)
{
	u8 data1;
	u8 data2;
		
	if(pData == NULL || !Read(&data1) || !Read(&data2))
	return 0;

	*pData = data1 << 8 | data2 << 0;

	return 1;
}

int CBuffer::Write(const int data)
{
	u8 data1 = (u8) ((data >> 24) & 0xFF);
	u8 data2 = (u8) ((data >> 16) & 0xFF);
	u8 data3 = (u8) ((data >> 8) & 0xFF);
	u8 data4 = (u8) ((data >> 0) & 0xFF);
	 
	return Write(data1) &&  Write(data2) && Write(data3) &&  Write(data4);
}

int CBuffer::Read(int* pData)
{
	u8 data1;
	u8 data2;
	u8 data3;
	u8 data4;
		
	if(pData == NULL || !Read(&data1) || !Read(&data2)
					 || !Read(&data3) || !Read(&data4))
	return 0;

	*pData = data1 << 24 | data2 << 16 | data3 << 8 | data4 << 0;

	return 1;
}

int CBuffer::Write(const u32 data)
{
	u8 data1 = (u8) ((data >> 24) & 0xFF);
	u8 data2 = (u8) ((data >> 16) & 0xFF);
	u8 data3 = (u8) ((data >> 8) & 0xFF);
	u8 data4 = (u8) ((data >> 0) & 0xFF);
	 
	return Write(data1) &&  Write(data2) && Write(data3) &&  Write(data4);
}

int CBuffer::Read(u32* pData)
{
	u8 data1;
	u8 data2;
	u8 data3;
	u8 data4;
		
	if(pData == NULL || !Read(&data1) || !Read(&data2)
					 || !Read(&data3) || !Read(&data4))
	return 0;

	*pData = data1 << 24 | data2 << 16 | data3 << 8 | data4 << 0;

	return 1;
}

CObject::u8* CBuffer::GetBuffer() const
{
	return buffer;
}

CObject::u32 CBuffer::GetBufferSize() const
{
	return bufferSize;
}

CObject::u32 CBuffer::GetReadPos() const
{
	return readPos;
}

CObject::u32 CBuffer::GetWritePos() const
{
	return writePos;
}

int CBuffer::IsEmpty() const
{
	return isEmpty;
}

int CBuffer::IsNotEmpty() const
{
	return !IsEmpty();
}

int CBuffer::SetReadPos(u32 readPos)
{
	if(IsEmpty())
	return 0;

	if(GetBufferSize() <= readPos)
	return 0;

	this->readPos = readPos;

	return 1;
}

int CBuffer::SetWritePos(u32 writePos)
{
	if(IsEmpty())
	return 0;

	if(GetBufferSize() <= writePos)
	return 0;

	this->writePos = writePos;

	return 1;
}


void CBuffer::Wipe()
{
	if(IsEmpty())
	return;

	for(u32 i = 0 ; i < GetBufferSize() ; i++)
	buffer[i] = 0;
}


void CBuffer::Init()
{
	buffer = NULL;
	bufferSize = 0;
	isEmpty = 1;

	readPos = 0;
	writePos = 0;
}

void CBuffer::ReInit()
{
	if(buffer)
	delete[] buffer;
		
	Init();
}

void CBuffer::SetEmpty()
{
	isEmpty = 1;
}
	
void CBuffer::SetNotEmpty()
{
	isEmpty = 0;
}
