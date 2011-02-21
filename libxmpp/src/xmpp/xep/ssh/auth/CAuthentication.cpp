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
#include <cstring>

#include "CAuthentication.h"
#include <pwd.h>

#ifdef __LINUX__
#ifndef __ANDROID__
#include <shadow.h>
#endif// __ANDROID__
#endif// __LINUX__

using namespace std;

CAuthentication::CAuthentication()
{}

CAuthentication::~CAuthentication()
{

}

bool CAuthentication::Authenticate(const string& userName, const string& password)
{	
	#ifdef __LINUX__
	// TODO: support SHA512 auth, disabled for now
	//if(!AuthenticateOnShadow(userName, password))
	//return false;
	#endif// __LINUX__

	#ifdef __APPLE__
	if(!AuthenticateOnDirectoryService(userName, password))
	return false;
	#endif// __APPLE__

	SetAttributes(userName);

	return true;
}

const string& CAuthentication::GetUserName() const
{
	return userName;
}

const string& CAuthentication::GetHomePath() const
{
	return homePath;
}

const string& CAuthentication::GetShell() const
{
	return shell;
}

const CObject::u32 CAuthentication::GetUID() const
{
	return uid;
}

const CObject::u32 CAuthentication::GetGID() const
{
	return gid;
}

void CAuthentication::SetAttributes(const string& userName)
{
#ifdef __ANDROID__
	this->userName = "root";
	uid = 0;
	gid = 0;
	homePath = "/data/local";
	shell = "/system/xbin/bash";

#else
	passwd* pPassword = getpwnam(userName.c_str());

	if(pPassword == NULL)
	throw CAuthenticationException(CAuthenticationException::AEC_SETATTRIBUTESERROR);
	
	this->userName = userName;
	uid = pPassword->pw_uid;
	gid = pPassword->pw_gid;
	homePath = pPassword->pw_dir; 
	shell = pPassword->pw_shell;
#endif// __ANDROID__
}

#ifdef __LINUX__

#ifdef __ANDROID__
bool CAuthentication::AuthenticateOnShadow(const string& userName, const string& password)
{
	return true;
}
#else
bool CAuthentication::AuthenticateOnShadow(const string& userName, const string& password)
{
	spwd* pPassword = getspnam(userName.c_str());

	if(pPassword == NULL)
	return false;

	if(strcmp(pPassword->sp_pwdp, crypt(password.c_str(), pPassword->sp_pwdp)) != 0)
	return false;

	return true;
}
#endif// __ANDROID__

#endif// __LINUX__

#ifdef __APPLE__

bool CAuthentication::AuthenticateOnDirectoryService(const string& userName, const string& password)
{
	tDirReference _directoryRef = 0;
	tDirStatus status = dsOpenDirService(&_directoryRef);
	
	if (status != eDSNoErr)
		return status;

	do {
		KADirectoryNode *node = NULL;
		
		status = KADirectoryClientGetNode(_directoryRef, eDSSearchNodeName, &node);
		
		if (status) break;
			
		CFArrayRef user_records = find_user_records_by_name(node, userName.c_str());

		if (!user_records) { status = eDSRecordNotFound; break; }
		
		CFDictionaryRef user_record = (CFDictionaryRef)CFArrayGetValueAtIndex(user_records, 0);
		
		if (!user_record) { status = eDSRecordNotFound; break; }
			
		KADirectoryNode *authNode = KADirectoryNodeCreateFromUserRecord(_directoryRef, user_record);

		if (!authNode) { status = eDSNodeNotFound; break; }

		status = authenticate_user_to_node(authNode, userName.c_str(), password.c_str());
	
	} while (false);
	
	dsCloseDirService(_directoryRef);
	
	return status == eDSNoErr;
}

void CAuthentication::KADirectoryNodeFree(KADirectoryNode *instance)
{
	if (instance->_name) 
		free(instance->_name);

    if (instance->_dataBufferPtr)
		dsDataBufferDeAllocate(instance->_directoryRef, instance->_dataBufferPtr);

    if (instance->_nodeRef)
        dsCloseDirNode(instance->_nodeRef);
		
	free(instance);
}

CAuthentication::KADirectoryNode* CAuthentication::KADirectoryNodeCreateFromUserRecord(tDirReference directoryRef, CFDictionaryRef user_record)
{
	KADirectoryNode* auth_node = NULL;
	const void* metanode_name = NULL;
	
	if (!user_record)
		return NULL;
	
	do
	{
		if (!CFDictionaryGetValueIfPresent(user_record, CFSTR(kDSNAttrMetaNodeLocation), &metanode_name) || !metanode_name)
			break;

		if (CFStringGetTypeID() != CFGetTypeID(metanode_name))
			break;
		
		char metanode_name_cstring[1024];
		if (!CFStringGetCString((CFStringRef)metanode_name, metanode_name_cstring, sizeof(metanode_name_cstring), kCFStringEncodingUTF8))
			break;

		tDataListPtr metanode_name_list_ptr = dsBuildFromPath(directoryRef, metanode_name_cstring, "/");
		
		if (!metanode_name_list_ptr)
			break;

		auth_node = KADirectoryNodeCreate(directoryRef, metanode_name_list_ptr);

		dsDataListDeallocate(directoryRef, metanode_name_list_ptr);
	} 
	while (false);
	
	return auth_node;
}

CAuthentication::KADirectoryNode* CAuthentication::KADirectoryNodeCreate(tDirReference directoryRef, tDataListPtr nodePtr)
{
	KADirectoryNode *instance = (KADirectoryNode*) calloc(1, sizeof(KADirectoryNode));
	if (!instance)
		return NULL;

	do {
		instance->_directoryRef = directoryRef;

		tDirStatus status = dsOpenDirNode(instance->_directoryRef, nodePtr, &instance->_nodeRef);
		if (status != eDSNoErr)
			break;
			
		instance->_dataBufferPtr = dsDataBufferAllocate(instance->_directoryRef, 2048);
		if (!instance->_dataBufferPtr)
			break;
		
		instance->_name = dsGetPathFromList(instance->_directoryRef, nodePtr, "/");
		if (!instance->_name)
			break;
			
		return instance;
	}
	while (false);

	KADirectoryNodeFree(instance);
	return NULL;
}



tDataBufferPtr CAuthentication::double_databuffer_or_bail(tDirReference directoryRef, tDataBufferPtr dataBufferPtr)
{
	unsigned long newBufferSize = 1024;
	if (dataBufferPtr)
	{
		newBufferSize = dataBufferPtr->fBufferSize * 2;
		dsDataBufferDeAllocate(directoryRef, dataBufferPtr);
		if (newBufferSize > 1024*1024)
			return NULL;
	}
	return dsDataBufferAllocate(directoryRef, newBufferSize);
}

tDirStatus CAuthentication::KADirectoryClientGetNode(tDirReference directoryRef, tDirPatternMatch pattern, KADirectoryNode **node)
{
    tDirStatus status = eDSNoErr;	
    unsigned long node_count = 0;
    tContextData continuation_data_ptr = NULL;
	tDataBufferPtr _dataBufferPtr = dsDataBufferAllocate(directoryRef, 1024);
	
	for (;;)
	{
		status = dsFindDirNodes(directoryRef, _dataBufferPtr, NULL, pattern, &node_count, &continuation_data_ptr);

		if ((status != eDSBufferTooSmall) || !(_dataBufferPtr = double_databuffer_or_bail(directoryRef,_dataBufferPtr)))
			break;
	}

    if (status == eDSNoErr)
	{
		tDataListPtr node_name_ptr = NULL;

		if (continuation_data_ptr)
			dsReleaseContinueData(directoryRef, continuation_data_ptr);

		// eDSNoNodeFound would've been returned already
		assert( node_count > 0 );
		
		status = dsGetDirNodeName(directoryRef, _dataBufferPtr,
								  1, // get first node
								  &node_name_ptr);

		if (status == eDSNoErr)
		{
			if (node)
				*node = KADirectoryNodeCreate(directoryRef, node_name_ptr);
			dsDataListDeallocate(directoryRef, node_name_ptr);
		}
	}
	
    if (_dataBufferPtr)
		dsDataBufferDeAllocate(directoryRef, _dataBufferPtr);

	return status;
}

CFMutableDictionaryRef CAuthentication::get_record_attributes(KADirectoryNode *node, tRecordEntryPtr record_entry_ptr, tAttributeListRef attr_list_ref)
{
	unsigned long rec_attr_count = record_entry_ptr->fRecordAttributeCount, i, j;
	
	CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, rec_attr_count, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!attributes)
		return NULL;
	
    for (i=1; i<= rec_attr_count; i++)
    {
        tAttributeValueListRef attr_value_list_ref;
        tAttributeEntryPtr attr_info_ptr;
        dsGetAttributeEntry( node->_nodeRef, node->_dataBufferPtr, attr_list_ref, i,
                             &attr_value_list_ref, &attr_info_ptr );
        unsigned long attr_value_count = attr_info_ptr->fAttributeValueCount;
		
		CFStringRef key = CFStringCreateWithBytes(kCFAllocatorDefault, 
								(const UInt8 *)attr_info_ptr->fAttributeSignature.fBufferData, 
								attr_info_ptr->fAttributeSignature.fBufferLength,
								kCFStringEncodingUTF8,
								false);
		
		CFMutableArrayRef values = NULL;
		if (attr_value_count > 1)
		{
			values = CFArrayCreateMutable(kCFAllocatorDefault, attr_value_count, &kCFTypeArrayCallBacks);
			if (!values)
				return NULL;
		}
		
		CFStringRef value = NULL;
		for (j=1; j <= attr_value_count; j++)
		{
			tAttributeValueEntryPtr value_entry_ptr;
			if (!dsGetAttributeValue( node->_nodeRef, node->_dataBufferPtr, j, attr_value_list_ref, &value_entry_ptr))
			{
				value = CFStringCreateWithBytes(kCFAllocatorDefault, 
							(const UInt8 *)value_entry_ptr->fAttributeValueData.fBufferData, 
							value_entry_ptr->fAttributeValueData.fBufferLength,
							kCFStringEncodingUTF8,
							false);
				if (value)
				{
					if (attr_value_count > 1)
					{
						CFArrayAppendValue(values, value);
						CFRelease(value);
					}
				}
			}
		}

		if (attr_value_count > 1)
		{
			CFDictionaryAddValue(attributes, key, values);
			CFRelease(values);
		} else {
			CFDictionaryAddValue(attributes, key, value);
			CFRelease(value);
		}
		
		CFRelease(key);

        dsDeallocAttributeEntry(node->_directoryRef, attr_info_ptr);
        dsCloseAttributeValueList(attr_value_list_ref);
    }

	return attributes;
}

CFMutableDictionaryRef CAuthentication::get_record_at_index(KADirectoryNode *node, long unsigned index)
{
    tRecordEntryPtr record_entry_ptr = NULL; 
    tAttributeListRef attr_list_ref;
	CFMutableDictionaryRef attributes = NULL;
	
	assert(index > 0); // indexes start with 1
	
	if (dsGetRecordEntry(node->_nodeRef, node->_dataBufferPtr,
		index, // start count at 1
		&attr_list_ref, &record_entry_ptr) == eDSNoErr)
	{
		attributes = get_record_attributes(node, record_entry_ptr, attr_list_ref);
		dsCloseAttributeList(attr_list_ref);
		dsDeallocRecordEntry(node->_directoryRef, record_entry_ptr);
	}

	return attributes;
}

CFArrayRef CAuthentication::find_user_records_by_name(KADirectoryNode *node, const char *username)
{  
    tDirStatus status =( tDirStatus) 0;
    long unsigned record_count = 0; // This is an input variable too
    tContextData continuation_data_ptr = NULL;
    CFMutableArrayRef results = NULL;

	tDataListPtr recordTypeDataList = dsBuildListFromStrings(node->_directoryRef, kDSStdRecordTypeUsers, NULL);
	tDataListPtr returnAttributesDataList = dsBuildListFromStrings(node->_directoryRef, kDSAttributesAll, NULL);
    tDataListPtr record_name_ptr = dsBuildListFromStrings(node->_directoryRef, username, NULL);
	
	do {
	
		for (;;)
		{
			status = dsGetRecordList(node->_nodeRef, node->_dataBufferPtr,
				record_name_ptr, eDSExact,
				recordTypeDataList,
				returnAttributesDataList,
				false,	/* attr info and data */
				&record_count,
				&continuation_data_ptr);
				
			// Of all errors we only try to recover from eDSBufferTooSmall here
			if ((status != eDSBufferTooSmall) || !(node->_dataBufferPtr = double_databuffer_or_bail(node->_directoryRef, node->_dataBufferPtr)))
			break;
		} 

        if (status)
			break;
			
        if (record_count > 0) 
        {
			long unsigned i;

			if (!results)
				results = CFArrayCreateMutable(kCFAllocatorDefault, record_count, &kCFTypeArrayCallBacks);

			for (i=1; i <= record_count; i++)
			{
				CFMutableDictionaryRef record = get_record_at_index(node, i);
				
				if (record)
				{
					CFArrayAppendValue(results, record);
					CFRelease(record);
				}
			}
        }
        
    } while (continuation_data_ptr != NULL);

	if (record_name_ptr)
		dsDataListDeallocate(node->_directoryRef, record_name_ptr);
	if (recordTypeDataList)
	    dsDataListDeallocate(node->_directoryRef, recordTypeDataList);
	if (returnAttributesDataList)
	    dsDataListDeallocate(node->_directoryRef, returnAttributesDataList);
    if (continuation_data_ptr)
		dsReleaseContinueData(node->_nodeRef, continuation_data_ptr);

	return results;
}

tDirStatus CAuthentication::authenticate_user_to_node(KADirectoryNode *node, const char *username, const char *password)
{
    if (!username)
		return (tDirStatus) false;

    size_t ulNameLen = strlen(username);
    size_t ulPassLen = password ? strlen(password) : 0;

	dsBool authenticateOnly = true;
    tDataNodePtr _authType = dsDataNodeAllocateString (node->_directoryRef, kDSStdAuthNodeNativeNoClearText);
    tDataBufferPtr _authdataBufferPtr = dsDataBufferAllocate(node->_directoryRef, sizeof(ulNameLen) + ulNameLen + sizeof(ulPassLen) + ulPassLen);
    tDataBufferPtr _stepBufferPtr = dsDataBufferAllocate(node->_directoryRef, 2048);

    char *cpBuff = _authdataBufferPtr->fBufferData;
    memcpy(cpBuff, &ulNameLen, sizeof (ulNameLen));
    cpBuff += sizeof(ulNameLen);
    memcpy(cpBuff, username, ulNameLen);
    cpBuff += ulNameLen;
    memcpy(cpBuff, &ulPassLen, sizeof(ulPassLen));
    cpBuff += sizeof(ulPassLen);
    memcpy(cpBuff, password, ulPassLen);
    _authdataBufferPtr->fBufferLength = sizeof(ulNameLen) + ulNameLen + sizeof(ulPassLen) + ulPassLen;

    tDirStatus status = dsDoDirNodeAuth(node->_nodeRef, _authType, authenticateOnly, _authdataBufferPtr, _stepBufferPtr, 0);
    
    dsDataNodeDeAllocate(node->_directoryRef, _authType);
    dsDataBufferDeAllocate(node->_directoryRef, _authdataBufferPtr);
    dsDataBufferDeAllocate(node->_directoryRef, _stepBufferPtr);
    
	return status;
}

#endif // __APPLE__

CAuthenticationException::CAuthenticationException(int code) : CException(code)
{}

CAuthenticationException::~CAuthenticationException() throw()
{}
	
const char* CAuthenticationException::what() const throw()
{
	switch(GetCode())
	{
	case AEC_CONSTRUCTORERROR:
		return "CAuthentication::Constructor() error";
		
	case AEC_DESTRUCTORERROR:
		return "CAuthentication::Destructor() error";

	case AEC_SETATTRIBUTESERROR:
		return "CAuthentication::SetAttributes() error";

	default:
		return "CAuthentication: Unknown error";
	}
}
