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

#ifndef __CAES_H__
#define __CAES_H__

#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>

#include <openssl/aes.h>

using namespace std;

class CAes : public CObject
{
public:
	CAes();
	virtual ~CAes();

	void SetKey(const string& string);
	void SetKey(const CBuffer& rKey);
	
	void Encrypt(const CBuffer& rIn, CBuffer* pOut);
	void Decrypt(const CBuffer& rIn, CBuffer* pOut);

private:
	void EncryptInPadding();
	void EncryptOutPadding();
	
private:
	AES_KEY aesEncryptionKey;
	AES_KEY aesDecryptionKey;
	AES_KEY aesInPaddingKey;
	AES_KEY aesOutPaddingKey;

	CBuffer InitialEncryptionVector;
	CBuffer InitialDecryptionVector;
	CBuffer InitialInPaddingVector;
	CBuffer InitialOutPaddingVector;
	CBuffer InPadding;
	CBuffer OutPadding;
};

class CAesException : public CException
{
public:
	enum AesExceptionCode
	{
		AEC_CONSTRUCTORERROR,
		AEC_DESTRUCTORERROR
	};

public:
	CAesException(int code);
	virtual ~CAesException() throw();

	virtual const char* what() const throw();
};

#endif // __CAES_H__
