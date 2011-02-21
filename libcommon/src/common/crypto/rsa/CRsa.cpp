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
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>
#include <time.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/crypto/rsa/CRsa.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBuffer.h>

using namespace std;

CRsa::CRsa()
{}

CRsa::~CRsa()
{}

void CRsa::GenerateChallenge(u32 challengeSize, CBuffer* pChallenge)
{
	try
	{
		/* Have to be changed with a more secure seed */

		u8 seedBuffer[4];
		u32 seed = time(NULL);

		seedBuffer[0] = (seed >> 0) & 0xFF;
		seedBuffer[1] = (seed >> 8) & 0xFF;
		seedBuffer[2] = (seed >> 16) & 0xFF;
		seedBuffer[3] = (seed >> 24) & 0xFF;

		RAND_seed(seedBuffer, 4);

		pChallenge->Create(challengeSize);

		if(RAND_bytes(pChallenge->GetBuffer(), challengeSize) != 1)
		throw CRsaException(CRsaException::REC_GENERATECHALLENGEERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaException(CRsaException::REC_GENERATECHALLENGEERROR);
	}
}

void CRsa::EncryptChallenge(const CRsaKey& rRsaKey, const CBuffer& rIn, CBuffer* pOut)
{
	try
	{
		if(rIn.GetBufferSize() + 41 >= rRsaKey.GetKeySize())
		throw CRsaException(CRsaException::REC_ENCRYPTCHALLENGEERROR);

		pOut->Create(rRsaKey.GetKeySize());
		
		int ret = RSA_public_encrypt(rIn.GetBufferSize(), rIn.GetBuffer(), pOut->GetBuffer(), rRsaKey.GetRsaKey(), RSA_PKCS1_PADDING);
		
		if(ret == -1)
		throw CRsaException(CRsaException::REC_ENCRYPTCHALLENGEERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaException(CRsaException::REC_ENCRYPTCHALLENGEERROR);
	}
}

void CRsa::DecryptChallenge(const CRsaKey& rRsaKey, const CBuffer& rIn, CBuffer* pOut)
{
	try
	{
		if(rIn.GetBufferSize() != rRsaKey.GetKeySize())
		throw CRsaException(CRsaException::REC_DECRYPTCHALLENGEERROR);

		CBuffer Temp(rRsaKey.GetKeySize());
		
		int ret = RSA_private_decrypt(rIn.GetBufferSize(), rIn.GetBuffer(), Temp.GetBuffer(), rRsaKey.GetRsaKey(), RSA_PKCS1_PADDING);
		
		if(ret == -1)
		throw CRsaException(CRsaException::REC_DECRYPTCHALLENGEERROR);

		pOut->Create(ret);
		pOut->Write(Temp.GetBuffer(), ret);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaException(CRsaException::REC_DECRYPTCHALLENGEERROR);
	}
}

void CRsa::SignChallenge(const CRsaKey& rRsaKey, const CBuffer& rChallenge, CBuffer* pSignature)
{
	try
	{
		pSignature->Create(rRsaKey.GetKeySize());
		
		unsigned int sigSize;

		if(RSA_sign(1, rChallenge.GetBuffer(), rChallenge.GetBufferSize(), pSignature->GetBuffer(), &sigSize, rRsaKey.GetRsaKey()) == 0)
		throw CRsaException(CRsaException::REC_SIGNCHALLENGEERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaException(CRsaException::REC_SIGNCHALLENGEERROR);
	}
}

bool CRsa::VerifyChallenge(const CRsaKey& rRsaKey, const CBuffer& rChallenge, const CBuffer& rSignature)
{
	try
	{
		return RSA_verify(1, rChallenge.GetBuffer(), rChallenge.GetBufferSize(), rSignature.GetBuffer(), rSignature.GetBufferSize(), rRsaKey.GetRsaKey());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaException(CRsaException::REC_VERIFYCHALLENGEERROR);
	}
}

CRsaException::CRsaException(int code) : CException(code)
{}

CRsaException::~CRsaException() throw()
{
}

const char* CRsaException::what() const throw()
{
	switch(GetCode())
	{	
	case REC_ENCRYPTCHALLENGEERROR:
		return "CRsa::EncryptChallenge() error";
	
	case REC_DECRYPTCHALLENGEERROR:
		return "CRsa::DecryptChallenge() error";
	
	case REC_SIGNCHALLENGEERROR:
		return "CRsa::SignChallenge() error";
	
	case REC_VERIFYCHALLENGEERROR:
		return "CRsa::VerifyChallenge() error";
	
	default:
		return "CRsa: Unknown error";

	}
}

