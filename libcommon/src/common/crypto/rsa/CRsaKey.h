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
 
#ifndef __CRSAKEY_H__
#define __CRSAKEY_H__

#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>

#include <openssl/rsa.h>

using namespace std;

class CRsaKey : public CObject
{
public:
	CRsaKey();
	virtual ~CRsaKey();
	
	void GenerateKey(u16 keySize, u32 exponent);
	bool CheckKey();
	u16 GetKeySize() const;

	void GetFingerPrint(CBuffer* pBuffer);

	void SetPrivateKey(const CBuffer& rEBuffer, const CBuffer& rPBuffer, const CBuffer& rQBuffer);
	void SetPublicKey(const CBuffer& rEBuffer, const CBuffer& rNBuffer);
	
	void GetE(CBuffer* pEBuffer) const;
	void GetD(CBuffer* pDBuffer) const;
	void GetP(CBuffer* pPBuffer) const;
	void GetQ(CBuffer* pQBuffer) const;
	void GetN(CBuffer* pNBuffer) const;

	void SetE(const CBuffer& rEBuffer);
	void SetD(const CBuffer& rDBuffer);
	void SetP(const CBuffer& rPBuffer);
	void SetQ(const CBuffer& rQBuffer);
	void SetN(const CBuffer& rNBuffer);

	RSA* GetRsaKey() const;
	
	
	
private:
	RSA* pRsa;
};

class CRsaKeyException : public CException
{
public:
	enum RsaKeyExceptionCode
	{
		RKEC_CONSTRUCTORERROR,
		RKEC_DESTRUCTORERROR,
		RKEC_GENERATEKEYERROR,
		RKEC_SETPRIVATEKEYERROR,
		RKEC_SETPUBLICKEYERROR,
		RKEC_SETEERROR,
		RKEC_SETDERROR,
		RKEC_SETPERROR,
		RKEC_SETQERROR,
		RKEC_SETNERROR,
		RKEC_GETEERROR,
		RKEC_GETDERROR,
		RKEC_GETPERROR,
		RKEC_GETQERROR,
		RKEC_GETNERROR
	};

public:
	CRsaKeyException(int code);
	virtual ~CRsaKeyException() throw();

	virtual const char* what() const throw();
};

#endif // __CRSAKEY_H__
