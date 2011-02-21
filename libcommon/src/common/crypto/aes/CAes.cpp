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

#include <string.h>
#include <iostream>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/crypto/aes/CAes.h>
#include <common/data/CBuffer.h>

#include <openssl/aes.h>

using namespace std;

CAes::CAes()
{
	try
	{
		InitialEncryptionVector.Create(AES_BLOCK_SIZE);
		InitialDecryptionVector.Create(AES_BLOCK_SIZE);
		InitialInPaddingVector.Create(AES_BLOCK_SIZE);
		InitialOutPaddingVector.Create(AES_BLOCK_SIZE);
		InPadding.Create(AES_BLOCK_SIZE);
		OutPadding.Create(AES_BLOCK_SIZE);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		throw CAesException(CAesException::AEC_CONSTRUCTORERROR);
	}
}

CAes::~CAes()
{}

void CAes::SetKey(const string& string)
{
	CBuffer Buffer(32);

	for(u32 i = 0 ; i < Buffer.GetBufferSize() ; i++)
	Buffer.GetBuffer()[i] = string[i % string.size()];
	
	SetKey(Buffer);
}

void CAes::SetKey(const CBuffer& rKey)
{
	AES_set_encrypt_key(rKey.GetBuffer(), rKey.GetBufferSize() * 8, &aesEncryptionKey);
	AES_set_decrypt_key(rKey.GetBuffer(), rKey.GetBufferSize() * 8, &aesDecryptionKey);

	AES_set_encrypt_key(rKey.GetBuffer(), rKey.GetBufferSize() * 8, &aesInPaddingKey);
	AES_set_encrypt_key(rKey.GetBuffer(), rKey.GetBufferSize() * 8, &aesOutPaddingKey);

	InitialEncryptionVector.SetWritePos(0);
	InitialDecryptionVector.SetWritePos(0);
	InitialInPaddingVector.SetWritePos(0);
	InitialOutPaddingVector.SetWritePos(0);

	for(u8 i = 0 ; i < AES_BLOCK_SIZE ; i++)
	{
		InitialEncryptionVector.Write(i);
		InitialDecryptionVector.Write(i);
		InitialInPaddingVector.Write(i);
		InitialOutPaddingVector.Write(i);
		InPadding.Write(rKey.GetBuffer()[i % rKey.GetBufferSize()]);
		OutPadding.Write(rKey.GetBuffer()[i % rKey.GetBufferSize()]);
	}
}

void CAes::Encrypt(const CBuffer& rIn, CBuffer* pOut)
{
	u32 inSize = rIn.GetBufferSize();
	u32 offSet = 0;
	u32 numBlock = inSize / AES_BLOCK_SIZE;
	u8 paddSize = inSize % AES_BLOCK_SIZE;
	pOut->Create(inSize);
	
	for(u32 i = 0 ; i < numBlock ; i++)
	{
		AES_cbc_encrypt(offSet + rIn.GetBuffer(), offSet + pOut->GetBuffer(), AES_BLOCK_SIZE, &aesEncryptionKey, InitialEncryptionVector.GetBuffer(), AES_ENCRYPT);
		offSet += AES_BLOCK_SIZE;
	}
	
	if(paddSize == 0)
	return;
	
	EncryptOutPadding();

	for(u32 i = 0 ; i < paddSize ; i++)
	pOut->GetBuffer()[offSet + i] = rIn.GetBuffer()[offSet + i] ^ OutPadding.GetBuffer()[i];
}

void CAes::Decrypt(const CBuffer& rIn, CBuffer* pOut)
{
	u32 inSize = rIn.GetBufferSize();
	u32 offSet = 0;
	u32 numBlock = inSize / AES_BLOCK_SIZE;
	u8 paddSize = inSize % AES_BLOCK_SIZE;
	pOut->Create(inSize);
	
	for(u32 i = 0 ; i < numBlock ; i++)
	{
		AES_cbc_encrypt(offSet + rIn.GetBuffer(), offSet + pOut->GetBuffer(), AES_BLOCK_SIZE, &aesDecryptionKey, InitialDecryptionVector.GetBuffer(), AES_DECRYPT);
		offSet += AES_BLOCK_SIZE;
	}

	if(paddSize == 0)
	return;
		
	EncryptInPadding();

	for(u32 i = 0 ; i < paddSize ; i++)
	pOut->GetBuffer()[offSet + i] = rIn.GetBuffer()[offSet + i] ^ InPadding.GetBuffer()[i];
}

void CAes::EncryptInPadding()
{
	CBuffer Temp(AES_BLOCK_SIZE);
	AES_cbc_encrypt(InPadding.GetBuffer(), Temp.GetBuffer(), AES_BLOCK_SIZE, &aesInPaddingKey, InitialInPaddingVector.GetBuffer(), AES_ENCRYPT);
	
	for(u32 i = 0 ; i < AES_BLOCK_SIZE ; i++)
	InPadding.GetBuffer()[i] = Temp.GetBuffer()[i];
}

void CAes::EncryptOutPadding()
{
	CBuffer Temp(AES_BLOCK_SIZE);
	AES_cbc_encrypt(OutPadding.GetBuffer(), Temp.GetBuffer(), AES_BLOCK_SIZE, &aesOutPaddingKey, InitialOutPaddingVector.GetBuffer(), AES_ENCRYPT);
	
	for(u32 i = 0 ; i < AES_BLOCK_SIZE ; i++)
	OutPadding.GetBuffer()[i] = Temp.GetBuffer()[i];
}


CAesException::CAesException(int code) : CException(code)
{}

CAesException::~CAesException() throw()
{
}

const char* CAesException::what() const throw()
{
	switch(GetCode())
	{
	case AEC_CONSTRUCTORERROR:
		return "CAes::Constructor() error";

	case AEC_DESTRUCTORERROR:
		return "CAes::Destructor() error";
		
	default:
		return "CAes: Unknown error";

	}
}

