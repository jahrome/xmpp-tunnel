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

#ifndef __CAUTHENTICATION_H__
#define __CAUTHENTICATION_H__

#include <string>

#include <common/CException.h>
#include <common/CObject.h>

using namespace std;

#ifdef __APPLE__
/* framwork={DirectoryService, CoreFoundation} */
#include <CoreFoundation/CoreFoundation.h>
#include <DirectoryService/DirServices.h>
#include <DirectoryService/DirServicesConst.h>
#include <DirectoryService/DirServicesUtils.h>

#endif //__APPLE__

class CAuthentication : public CObject
{
public:
	CAuthentication();
	virtual ~CAuthentication();

	bool Authenticate(const string& userName, const string& password);

	const string& GetUserName() const;
	const string& GetHomePath() const;
	const string& GetShell() const;
	const u32 GetUID() const;
	const u32 GetGID() const;
	
protected :
	void SetAttributes(const string& userName);

#ifdef __APPLE__
	bool AuthenticateOnDirectoryService(const string& userName, const string& password);
#endif //__APPLE__

#ifdef __LINUX__
	bool AuthenticateOnShadow(const string& userName, const string& password);
#endif //__LINUX__

private :
	u32 uid;
	u32 gid;
	string userName;
	string homePath;
	string shell;

#ifdef __APPLE__
	typedef struct KADirectoryNode
	{
		tDirReference _directoryRef;
		tDirNodeReference _nodeRef;
		tDataBufferPtr _dataBufferPtr;
		char *_name;
	};

	CFMutableDictionaryRef get_record_at_index(KADirectoryNode *node, long unsigned index);
	CFMutableDictionaryRef get_record_attributes(KADirectoryNode *node, tRecordEntryPtr record_entry_ptr, tAttributeListRef attr_list_ref);
	tDirStatus KADirectoryClientGetNode(tDirReference directoryRef, tDirPatternMatch pattern, KADirectoryNode **node);
	CFArrayRef find_user_records_by_name(KADirectoryNode *node, const char *username);
	KADirectoryNode *KADirectoryNodeCreateFromUserRecord(tDirReference directoryRef, CFDictionaryRef user_record);
	tDirStatus authenticate_user_to_node(KADirectoryNode *node, const char *username, const char *password);
	tDataBufferPtr double_databuffer_or_bail(tDirReference directoryRef, tDataBufferPtr dataBufferPtr);
	KADirectoryNode *KADirectoryNodeCreate(tDirReference directoryRef, tDataListPtr nodePtr);
	void KADirectoryNodeFree(KADirectoryNode *instance);
#endif //__APPLE__
};

class CAuthenticationException : public CException
{
public:
	enum AuthenticationExceptionCode
	{
		AEC_CONSTRUCTORERROR,
		AEC_DESTRUCTORERROR,
		AEC_SETATTRIBUTESERROR
	};

public:
	CAuthenticationException(int code);
	virtual ~CAuthenticationException() throw();

	virtual const char* what() const throw();
};

#endif // __CAUTHENTICATION_H__
