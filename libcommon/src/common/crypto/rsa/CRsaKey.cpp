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
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBuffer.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>

using namespace std;

CRsaKey::CRsaKey()
{
	try
	{
		pRsa = RSA_new();
		
		if(pRsa == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_CONSTRUCTORERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_CONSTRUCTORERROR);
	}
}

CRsaKey::~CRsaKey()
{
	try
	{
		if(pRsa == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_DESTRUCTORERROR);
		
		RSA_free(pRsa);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

void CRsaKey::GenerateKey(u16 keySize, u32 exponent)
{
	try
	{
		BN_GENCB cb;
		int i;
		BIGNUM *e = BN_new();
		if(!pRsa || !e)
			throw CRsaKeyException(CRsaKeyException::RKEC_GENERATEKEYERROR);

		/* The problem is when building with 8, 16, or 32 BN_ULONG,
		 * unsigned long can be larger */
		for (i=0; i<(int)sizeof(unsigned long)*8; i++)
			{
			if (exponent & (1UL<<i))
				if (BN_set_bit(e,i) == 0)
					throw CRsaKeyException(CRsaKeyException::RKEC_GENERATEKEYERROR);
			}

		BN_GENCB_set_old(&cb, NULL, NULL);

		RSA_generate_key_ex(pRsa, keySize, e, &cb);
		BN_free(e);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_GENERATEKEYERROR);
	}
}

bool CRsaKey::CheckKey()
{
	return RSA_check_key(pRsa);
}

CObject::u16 CRsaKey::GetKeySize() const
{
	return RSA_size(pRsa);
}

void CRsaKey::GetFingerPrint(CBuffer* pBuffer)
{
	CBuffer EBuffer, NBuffer;
	GetE(&EBuffer);
	GetN(&NBuffer);

	pBuffer->Create(20);
	
	for(u32 i = 0 ; i < pBuffer->GetBufferSize() ; i++)
	pBuffer->GetBuffer()[i] = 0;


	for(u32 i = 0 ; i < EBuffer.GetBufferSize() ; i++)
	pBuffer->GetBuffer()[i % 20] ^= EBuffer.GetBuffer()[i];

	for(u32 i = 0 ; i < NBuffer.GetBufferSize() ; i++)
	pBuffer->GetBuffer()[i % 20] ^= NBuffer.GetBuffer()[i];

}


void CRsaKey::SetPrivateKey(const CBuffer& rEBuffer, const CBuffer& rPBuffer, const CBuffer& rQBuffer)
{
	try
	{
		SetE(rEBuffer);
		SetP(rPBuffer);
		SetQ(rQBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETPRIVATEKEYERROR);
	}
}

void CRsaKey::SetPublicKey(const CBuffer& rEBuffer, const CBuffer& rNBuffer)
{
	try
	{
		SetE(rEBuffer);
		SetN(rNBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETPUBLICKEYERROR);
	}
}

void CRsaKey::GetE(CBuffer* pEBuffer) const
{
	try
	{
		pEBuffer->Create(BN_num_bytes(pRsa->e));
		BN_bn2bin(pRsa->e, pEBuffer->GetBuffer());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_GETEERROR);
	}
}

void CRsaKey::GetP(CBuffer* pPBuffer) const
{
	try
	{
		pPBuffer->Create(BN_num_bytes(pRsa->p));
		BN_bn2bin(pRsa->p, pPBuffer->GetBuffer());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_GETPERROR);
	}
}

void CRsaKey::GetQ(CBuffer* pQBuffer) const
{
	try
	{
		pQBuffer->Create(BN_num_bytes(pRsa->q));
		BN_bn2bin(pRsa->q, pQBuffer->GetBuffer());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_GETQERROR);
	}
}

void CRsaKey::GetN(CBuffer* pNBuffer) const
{
	try
	{
		pNBuffer->Create(BN_num_bytes(pRsa->n));
		BN_bn2bin(pRsa->n, pNBuffer->GetBuffer());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_GETNERROR);
	}
}

void CRsaKey::GetD(CBuffer* pDBuffer) const
{
	try
	{
		pDBuffer->Create(BN_num_bytes(pRsa->d));
		BN_bn2bin(pRsa->d, pDBuffer->GetBuffer());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_GETDERROR);
	}
}

void CRsaKey::SetE(const CBuffer& rEBuffer)
{
	try
	{
		if(pRsa->e != NULL)
		{
			BN_free(pRsa->e);
			pRsa->e = NULL;
		}
		
		pRsa->e = BN_bin2bn(rEBuffer.GetBuffer(), rEBuffer.GetBufferSize(), NULL);
		
		if(pRsa->e == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_SETEERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETEERROR);
	}
}

void CRsaKey::SetD(const CBuffer& rDBuffer)
{
	try
	{
		if(pRsa->d != NULL)
		{
			BN_free(pRsa->d);
			pRsa->d = NULL;
		}
		
		pRsa->d = BN_bin2bn(rDBuffer.GetBuffer(), rDBuffer.GetBufferSize(), NULL);
		
		if(pRsa->d == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_SETDERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETDERROR);
	}
}

void CRsaKey::SetP(const CBuffer& rPBuffer)
{
	try
	{
		if(pRsa->p != NULL)
		{
			BN_free(pRsa->p);
			pRsa->p = NULL;
		}
		
		pRsa->p = BN_bin2bn(rPBuffer.GetBuffer(), rPBuffer.GetBufferSize(), NULL);
		
		if(pRsa->p == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_SETPERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETPERROR);
	}
}

void CRsaKey::SetQ(const CBuffer& rQBuffer)
{
	try
	{
		if(pRsa->q != NULL)
		{
			BN_free(pRsa->q);
			pRsa->q = NULL;
		}
		
		pRsa->q = BN_bin2bn(rQBuffer.GetBuffer(), rQBuffer.GetBufferSize(), NULL);
		
		if(pRsa->q == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_SETQERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETQERROR);
	}
}

void CRsaKey::SetN(const CBuffer& rNBuffer)
{
	try
	{
		if(pRsa->n != NULL)
		{
			BN_free(pRsa->n);
			pRsa->n = NULL;
		}
		
		pRsa->n = BN_bin2bn(rNBuffer.GetBuffer(), rNBuffer.GetBufferSize(), NULL);
		
		if(pRsa->n == NULL)
		throw CRsaKeyException(CRsaKeyException::RKEC_SETNERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CRsaKeyException(CRsaKeyException::RKEC_SETNERROR);
	}
}

RSA* CRsaKey::GetRsaKey() const
{
	return pRsa;
}

CRsaKeyException::CRsaKeyException(int code) : CException(code)
{}

CRsaKeyException::~CRsaKeyException() throw()
{
}

const char* CRsaKeyException::what() const throw()
{
	switch(GetCode())
	{
	case RKEC_CONSTRUCTORERROR:
		return "CRsaKey::Constructor() error";

	case RKEC_DESTRUCTORERROR:
		return "CRsaKey::Destructor() error";

	case RKEC_GENERATEKEYERROR:
		return "CRsaKey::GenerateKey() error";

	case RKEC_SETPRIVATEKEYERROR:
		return "CRsaKey::SetPrivateKey() error";

	case RKEC_SETPUBLICKEYERROR:
		return "CRsaKey::SetPublicKey() error";

	case RKEC_SETEERROR:
		return "CRsaKey::GetE() error";

	case RKEC_SETDERROR:
		return "CRsaKey::GetD() error";

	case RKEC_SETPERROR:
		return "CRsaKey::GetP() error";

	case RKEC_SETQERROR:
		return "CRsaKey::GetQ() error";

	case RKEC_SETNERROR:
		return "CRsaKey::GetN() error";
		
	case RKEC_GETEERROR:
		return "CRsaKey::GetE() error";

	case RKEC_GETDERROR:
		return "CRsaKey::GetD() error";

	case RKEC_GETPERROR:
		return "CRsaKey::GetP() error";

	case RKEC_GETQERROR:
		return "CRsaKey::GetQ() error";

	case RKEC_GETNERROR:
		return "CRsaKey::GetN() error";
		
	default:
		return "CRsaKey: Unknown error";

	}
}

