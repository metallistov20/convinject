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

/* stdout */
#include <stdio.h>

/* strlen() */
#include <string.h>

/* calloc() */
#include <stdlib.h>

/* Data structure type definition */
#include "cmds.h"


int _EnrollCmd(const char * caller, pCmdType * ppThisCmdChain, char * pcCmd)
{
pCmdType pChild, pTempCmdChain;

	if (NULL == *ppThisCmdChain)
	{
		/* only one chain, for beginning */
		*ppThisCmdChain = (pCmdType) calloc ( 1, sizeof (CmdType) );

		/* check if successful */
		if (NULL == *ppThisCmdChain)
		{
			printf("[%s] %s:%s : ERROR: can't allocate memory for first element. \n",
			__FILE__, caller, __func__);

			return (-8);//ERROR_MEM;
		}

#if 1
		/* fulfill data */
		(*ppThisCmdChain)->pcCmd = calloc (1, strlen (pcCmd) +1 );

		strcpy( (*ppThisCmdChain)->pcCmd, pcCmd);
#endif
	}
	else
	{
		/* point with first temporary element to head of chain */
		pChild = *ppThisCmdChain;

		pTempCmdChain = (pCmdType) calloc (1, sizeof (CmdType) );

		if (NULL == pTempCmdChain)
		{

			printf("[%s] %s:%s : ERROR: can't allocate memory for next element. \n", 
			__FILE__, caller, __func__);

			return (-8);//ERROR_MEM;
		}

#if 1
		/* fulfill data */
		pTempCmdChain->pcCmd = calloc (1, strlen (pcCmd) +1 );

		strcpy( pTempCmdChain->pcCmd, pcCmd);
#endif

		/* Skip everything, except last entry */
		while ( (NULL != pChild) && (NULL != pChild->pNext ) )
		{
			/* . . */
			pChild = pChild->pNext;
		}

		/* Next chunk was created allright (we know it at this moment), so we attach a new chain entry to the end of existing chain */
		pChild->pNext = pTempCmdChain;

	}

	return 0;//SUCCESS;

}

extern int fd[2];
#include "cmds.h"

/* Process data stored in dynamic structure pointed by 'pPointChainPar' */
static int ProcessSingleCmd(/* const char * caller, */pCmdType pPointChainPar)
{
//	/* Wait between commands */
//	sleep (BETW_CMD_TMO);

	/* Push next command from tray into second endpoint of pipe */
	write(fd[1], pPointChainPar->pcCmd, strlen (pPointChainPar->pcCmd) +  1);
}

/* Process data stored in dynamic structure pointed by 'pPointChainPar' */
int _ProcessCmds(const char * caller, pCmdType pPointChainPar)
{
pCmdType pPointChain = pPointChainPar;

	/* Process each entry of chain */
	while (NULL != pPointChain)
	{		
#if 1
		/* Realtime and relative-time values */
		ProcessSingleCmd(pPointChain);
#else
		printf ("PRINT OUT<pPointChainPar=%p>:%s\n", pPointChain, pPointChain->pcCmd);
#endif /* 0 */

		/* Go to next record of chain */
		pPointChain = pPointChain->pNext;
	}

	return 0;//SUCCESS;

}

/* Free memory occupied by '*ppThisCmdChain' */
void _DeleteCmd(const char * caller, pCmdType * ppThisCmdChain)
{
pCmdType pChild, pThisCmdChain = *ppThisCmdChain;

	/* Walk through entire list and delete each chain */
	while (NULL != pThisCmdChain)
	{
		/* if space to keep item's name is allocated */
		if (pThisCmdChain->pcCmd)
		
		    /* then release this space */
		    free(pThisCmdChain->pcCmd);

		/* preserve a pointer to next record */		    
		pChild = pThisCmdChain->pNext;
		
		/* free space occupied by current record */
		free (pThisCmdChain);
		
		/* Go to next record */
		pThisCmdChain = pChild;
	}

	/* Dispose first element of chain */
	*ppThisCmdChain = NULL;

}



