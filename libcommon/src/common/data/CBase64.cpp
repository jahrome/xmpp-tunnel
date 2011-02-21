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
#include <stdio.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBase64.h>
#include <common/data/CBuffer.h>

using namespace std;

CBase64::CBase64()
{
	int k = 0;
	
	for(int i = 0 ; i < 26 ; i++)
	base64[k++] = 'A' + i;

	for(int i = 0 ; i < 26 ; i++)
	base64[k++] = 'a' + i;

	for(int i = 0 ; i < 10 ; i++)
	base64[k++] = '0' + i;

	base64[k++] = '+';
	base64[k++] = '/';
	base64[k++] = '=';
	
	padOffset = 64;
}

CBase64::~CBase64()
{}

void CBase64::To64(CBuffer* pBufferIn, string& strOut)
{
	try
	{
		strOut = "";
		pBufferIn->SetReadPos(0);

		u8 byte1, byte2, byte3;

		for(u32 i = 0 ; i < pBufferIn->GetBufferSize() / 3 ; i++)
		{
			pBufferIn->Read(&byte1);
			pBufferIn->Read(&byte2);
			pBufferIn->Read(&byte3);
			
			strOut += base64[byte1 >> 2];
			strOut += base64[((byte1 & 0x03) << 4) | (byte2 >> 4)];
			strOut += base64[((byte2 & 0xF) << 2) | (byte3 >> 6)];
			strOut += base64[byte3 & 0x3F];
		}

		if(pBufferIn->GetBufferSize() % 3 == 1)
		{
			pBufferIn->Read(&byte1);
		
			strOut += base64[byte1 >> 2];
			strOut += base64[(byte1 & 0x03) << 4];
			strOut += base64[padOffset];
			strOut += base64[padOffset];
		}

		if(pBufferIn->GetBufferSize() % 3 == 2)
		{
			pBufferIn->Read(&byte1);
			pBufferIn->Read(&byte2);
			
			strOut += base64[byte1 >> 2];
			strOut += base64[((byte1 & 0x03) << 4) | (byte2 >> 4)];
			strOut += base64[(byte2 & 0xF) << 2];
			strOut += base64[padOffset];
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CBase64Exception(CBase64Exception::B64EC_TO64ERROR);
	}
}

void CBase64::To64(CBuffer* pBufferIn, CBuffer* pBufferOut)
{
	try
	{
		u32 bufferOutSize;
		pBufferIn->SetReadPos(0);

		bufferOutSize = (pBufferIn->GetBufferSize() / 3) * 4;

		if(pBufferIn->GetBufferSize() % 3)
		bufferOutSize += 4;

		pBufferOut->Create(bufferOutSize);

		u8 byte1, byte2, byte3;

		for(u32 i = 0 ; i < pBufferIn->GetBufferSize() / 3 ; i++)
		{
			pBufferIn->Read(&byte1);
			pBufferIn->Read(&byte2);
			pBufferIn->Read(&byte3);
			
			pBufferOut->Write(base64[byte1 >> 2]);
			pBufferOut->Write(base64[((byte1 & 0x03) << 4) | (byte2 >> 4)]);
			pBufferOut->Write(base64[((byte2 & 0xF) << 2) | (byte3 >> 6)]);
			pBufferOut->Write(base64[byte3 & 0x3F]);
		}

		if(pBufferIn->GetBufferSize() % 3 == 1)
		{
			pBufferIn->Read(&byte1);
		
			pBufferOut->Write(base64[byte1 >> 2]);
			pBufferOut->Write(base64[(byte1 & 0x03) << 4]);
			pBufferOut->Write(base64[padOffset]);
			pBufferOut->Write(base64[padOffset]);
		}

		if(pBufferIn->GetBufferSize() % 3 == 2)
		{
			pBufferIn->Read(&byte1);
			pBufferIn->Read(&byte2);
			
			pBufferOut->Write(base64[byte1 >> 2]);
			pBufferOut->Write(base64[((byte1 & 0x03) << 4) | (byte2 >> 4)]);
			pBufferOut->Write(base64[(byte2 & 0xF) << 2]);
			pBufferOut->Write(base64[padOffset]);
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CBase64Exception(CBase64Exception::B64EC_TO64ERROR);
	}
}

void CBase64::From64(const string& strIn, CBuffer* pBufferOut)
{
	try
	{
		if(strIn.size() == 0)
		return;
		
		if(strIn.size() % 4)
		throw CBase64Exception(CBase64Exception::B64EC_FROM64ERROR);
		
		int offset1 = GetOffset(strIn[strIn.size() - 2]);
		int offset2 = GetOffset(strIn[strIn.size() - 1]);
		
		uInt32 bufferOutSize;
		
		bufferOutSize = (strIn.size() /  4) * 3;

		if(offset1 == padOffset && offset2 == padOffset)
		bufferOutSize -= 2;

		if(offset1 != padOffset && offset2 == padOffset)
		bufferOutSize -= 1;

		pBufferOut->Create(bufferOutSize);

		for(uInt32 i = 0 ; i < strIn.size() ; i += 4)
		{
			uByte byte;

			/* convert each ascii char to offset */
			int offset1 = GetOffset(strIn[i + 0]);
			int offset2 = GetOffset(strIn[i + 1]);
			int offset3 = GetOffset(strIn[i + 2]);
			int offset4 = GetOffset(strIn[i + 3]);
			
			/* case if  */
			if(offset3 == padOffset && offset4 == padOffset)
			{
				byte = (offset1 << 2) | (offset2 >> 4);
				pBufferOut->Write(byte);
				
				return;
			}

			if(offset3 != padOffset && offset4 == padOffset)
			{
				byte = (offset1 << 2) | (offset2 >> 4);
				pBufferOut->Write(byte);
				
				byte = (offset2 << 4) | (offset3 >> 2);
				pBufferOut->Write(byte);
			
				return;
			}
			
			byte = (offset1 << 2) | (offset2 >> 4);
			pBufferOut->Write(byte);
			
			byte = (offset2 << 4) | (offset3 >> 2);
			pBufferOut->Write(byte);
			
			byte = (offset3 << 6) | (offset4);
			pBufferOut->Write(byte);
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CBase64Exception(CBase64Exception::B64EC_FROM64ERROR);
	}
}

void CBase64::From64(CBuffer* pBufferIn, CBuffer* pBufferOut)
{
	try
	{
		if(pBufferIn->GetBufferSize() == 0)
		return;
		
		if(pBufferIn->GetBufferSize() % 4)
		throw CBase64Exception(CBase64Exception::B64EC_FROM64ERROR);
		
		pBufferIn->SetReadPos(pBufferIn->GetBufferSize() - 2);

		int offset1 = GetOffset(pBufferIn->GetByte());
		int offset2 = GetOffset(pBufferIn->GetByte());
		
		uInt32 bufferOutSize;
		
		bufferOutSize = (pBufferIn->GetBufferSize() /  4) * 3;

		if(offset1 == padOffset && offset2 == padOffset)
		bufferOutSize -= 2;

		if(offset1 != padOffset && offset2 == padOffset)
		bufferOutSize -= 1;

		pBufferOut->Create(bufferOutSize);

		pBufferIn->SetReadPos(0);

		for(uInt32 i = 0 ; i < pBufferIn->GetBufferSize() / 4; i++)
		{
			uByte byte;

			/* convert each ascii char to offset */
			int offset1 = GetOffset(pBufferIn->GetByte());
			int offset2 = GetOffset(pBufferIn->GetByte());
			int offset3 = GetOffset(pBufferIn->GetByte());
			int offset4 = GetOffset(pBufferIn->GetByte());
			
			/* case if  */
			if(offset3 == padOffset && offset4 == padOffset)
			{
				byte = (offset1 << 2) | (offset2 >> 4);
				pBufferOut->Write(byte);
				
				return;
			}

			if(offset3 != padOffset && offset4 == padOffset)
			{
				byte = (offset1 << 2) | (offset2 >> 4);
				pBufferOut->Write(byte);
				
				byte = (offset2 << 4) | (offset3 >> 2);
				pBufferOut->Write(byte);
			
				return;
			}
			
			byte = (offset1 << 2) | (offset2 >> 4);
			pBufferOut->Write(byte);
			
			byte = (offset2 << 4) | (offset3 >> 2);
			pBufferOut->Write(byte);
			
			byte = (offset3 << 6) | (offset4);
			pBufferOut->Write(byte);
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CBase64Exception(CBase64Exception::B64EC_FROM64ERROR);
	}
}


int CBase64::GetOffset(char car)
{
	try
	{
		if('A' <= car && car <= 'Z')
		return car - 'A';

		if('a' <= car && car <= 'z')
		return (car - 'a') + 26;

		if('0' <= car && car <= '9')
		return (car - '0') + 52;

		if(car == '+')
		return 62;

		if(car == '/')
		return 63;
		
		if(car == '=')
		return padOffset;

		throw CBase64Exception(CBase64Exception::B64EC_GETOFFSETERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CBase64Exception(CBase64Exception::B64EC_GETOFFSETERROR);
	}
}

CBase64Exception::CBase64Exception(int code) : CException(code)
{}

CBase64Exception::~CBase64Exception() throw()
{}
	
const char* CBase64Exception::what() const throw()
{
	switch(GetCode())
	{
	case B64EC_GETOFFSETERROR:
		return "CBase64::GetOffset() error";
	
	case B64EC_FROM64ERROR:
		return "CBase64::From64() error";

	case B64EC_TO64ERROR:
		return "CBase64::To64() error";
		
	default:
		return "CBase64: Unknown error";
	}

}



