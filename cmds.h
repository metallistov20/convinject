/*
 (C) Copyright 2016, TP-Link Inc, konstantin.mauch@tp-link.com

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; either version 2 of
 the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT any WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 MA 02111-1307 USA
*/

#ifndef _CMDS_H_
#define _CMDS_H_


typedef struct _CmdType
{
	/* String to point to Command */
	char * pcCmd;

	/* Next time point in the chain */
	struct _CmdType * pNext;

} CmdType, *pCmdType;


int _EnrollCmd(const char * caller, pCmdType * ppThisPointChain, char * pcCmd);

int _ProcessCmds(const char * caller, pCmdType pCmdChainPar);

void _DeleteCmd(const char * caller, pCmdType * ppThisCmdChain);


#define EnrollCmd(x, y) _EnrollCmd(__func__, (x), (y))

#define ProcessCmds(x) _ProcessCmds(__func__, (x))

#define DeleteCmd(x) _DeleteCmd(__func__, (x))


#endif /* _CMDS_H_ */
