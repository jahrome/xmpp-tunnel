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
 
#ifndef __CBUFFER_H__
#define __CBUFFER_H__

#include <string>

#include <common/CException.h>
#include <common/CObject.h>

using namespace std;

class CBuffer : public CObject
{
public:
	CBuffer();
	CBuffer(u32 bufferSize);
	CBuffer(const CBuffer* pBuffer);
	virtual ~CBuffer();
 
 	void ReInit();
	int Create(u32 bufferSize);
	int Affect(const char str[]);
	int Affect(const string& str);	
	int Affect(const CBuffer* pBuffer);
	int Attach(const CBuffer* pBuffer);

	u8 GetByte();

	int Write(const u8* pData, u32 dataSize);
	int Read(u8* pData, u32 dataSize);

	int Write(const string& data);
	int Write(const string* pData);
	
	int Write(const char pData[]);
	int Read(char* pData, u32 dataSize);

	int Write(const CBuffer* pBuffer);
	int Read(CBuffer* pBuffer);

	int Write(const char data);
	int Read(char* pData);

	int Write(const u8 data);
	int Read(u8* pData);

	int Write(const uInt16 data);
	int Read(uInt16* pData);

	int Write(const int data);
	int Read(int* pData);

	int Write(const u32 data);
	int Read(u32* pData);

	u8* GetBuffer() const;
	u32 GetBufferSize() const;

	u32 GetReadPos() const;
	u32 GetWritePos() const;

	int IsEmpty() const;
	int IsNotEmpty() const;

	int SetReadPos(u32 readPos);
	int SetWritePos(u32 writePos);

	void Wipe();

private:
	void Init();

	void SetEmpty();
	void SetNotEmpty();

private:
	u8* buffer;
	u32 bufferSize;
	bool isEmpty;
	bool isAttached;
	
	u32 readPos;
	u32 writePos;	
};
 
#endif // __CBUFFER_H__
