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

 /*******************************************************************************************/
 /*                            [TODO : Automator implementation]                            */
 /* AddTransition    (startStat, event, endStat) : add a new stat in the automator graph    */
 /* InsertTransition (startStat, eventStart, eventEnd, endStat) : insert a stat between two */
 /* Record Transition (stack limitation) peut etre pas mal util au debuggage                */
 /*******************************************************************************************/

#ifndef __COBJECT_H__
#define __COBJECT_H__

class CObject
{
public:
	typedef unsigned char uByte;
	typedef unsigned char uInt8;
	typedef unsigned short uInt16;
	typedef unsigned long uInt32;
	typedef unsigned char u8;
	typedef unsigned short u16;
	typedef unsigned long u32;
	typedef signed char s8;
	typedef signed short s16;
	typedef signed long s32;

public:
	CObject();
	virtual ~CObject();
	
protected:

};

#endif // __COBJECT_H__
