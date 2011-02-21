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
 
#ifndef __CRSA_H__
#define __CRSA_H__

#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/crypto/rsa/CRsaKey.h>

#include <openssl/rsa.h>

using namespace std;

class CRsa : public CObject
{
public:
	CRsa();
	virtual ~CRsa();
	
	static void GenerateChallenge(u32 challengeSize, CBuffer* pChallenge);

	static void EncryptChallenge(const CRsaKey& rRsaKey, const CBuffer& rIn, CBuffer* pOut);
	static void DecryptChallenge(const CRsaKey& rRsaKey, const CBuffer& rIn, CBuffer* pOut);

	static void SignChallenge(const CRsaKey& rRsaKey, const CBuffer& rChallenge, CBuffer* pSignature);
	static bool VerifyChallenge(const CRsaKey& rRsaKey, const CBuffer& rChallenge, const CBuffer& rSignature);
};

class CRsaException : public CException
{
public:
	enum RsaExceptionCode
	{
		REC_GENERATECHALLENGEERROR,
		REC_ENCRYPTCHALLENGEERROR,
		REC_DECRYPTCHALLENGEERROR,
		REC_SIGNCHALLENGEERROR,
		REC_VERIFYCHALLENGEERROR
	};

public:
	CRsaException(int code);
	virtual ~CRsaException() throw();

	virtual const char* what() const throw();
};

#endif // __CRSA_H__
