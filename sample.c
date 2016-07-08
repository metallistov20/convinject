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

#include "config.h"

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <sys/select.h>

#include <sys/time.h>

#include <fcntl.h>

#ifdef HAVE_TERMIOS_H
	#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
	#include <unistd.h>
#endif
#ifdef HAVE_PTY_H
	#include <pty.h>
#endif

#include <sys/ioctl.h>

#include <signal.h>

#include <errno.h>

#include <fcntl.h>

#include <libssh/callbacks.h>

#include <libssh/libssh.h>

#include <libssh/sftp.h>


#include "examples_common.h"

#include <unistd.h>


#define MAXCMD 10

static char *host;

static char *user;

static char *cmds[MAXCMD];

static struct termios terminal;

static char *pcap_file=NULL;

static char *proxycommand;

#define DATA_FNAME "local_data.txt"

#include "cmds.h"

/* Pointer to a dynamic structure to store command tray */
pCmdType pCmdChain;



/* Initiate forked process with marker 'cpMrk' to run not longer than 'iTMO' seconds */
int iInput_Start(char * cpMrk, int iTMO);

/* */
int iOutput_Start(char * cpMrk, int iTMO);

/* Son process has terminated itself correcly */
#define FORK_SUCCESS 		(0)

/* Not defined condition of forked process(es) */
#define FORK_UNDEFINED 		(-1)

/* Code for exiting from forked process */
#define FORK_EXITCODE		(99)

/* Max length of command */
#define SINGLE_CMD_MAXLENGHT	256

/* Amount of comands in array */
#define CMD_ARR_LENGHT		8

/* File open error */
#define FO_ERROR		(-7)

/* Type of command */
typedef char CMD_TYPE[SINGLE_CMD_MAXLENGHT];

/* Array with commands, a.k.a. commad tray */
CMD_TYPE cCmdData[CMD_ARR_LENGHT];

/* Single command buffer */
CMD_TYPE cCmdDataBuf;

/* Name of process to terminate on timeout */
static int g_iChildPID;

/* Pipe to maintain communication between parent and child */
int input_pipe[2];

#if defined(OUT_PIPE)
/* Pipe to ... TODO add comment */
int output_pipe[2];
#endif /* OUT_PIPE */


/*
* Parameters:
*	'cpMrk' - marker to define forked process 
*	'iTMO' - amount of seconds to wait before forced cancellation
*/
int iInput_Start(char *cpMrk, int iTMO) 
{
/* Return code to define whether the child process was launched */
int iRet = FORK_UNDEFINED;

	/* Assign initial value */
	g_iChildPID = -1;

	g_iChildPID = fork();

	printf("New pid=%d \n", g_iChildPID);

	/* Parent process */
	if ( 0 < g_iChildPID ) 
	{
		/* Parent should not undertake anny activity in this position */
	}



	/* Child process */
	else if (0 == g_iChildPID)
	{
	int iChld = CMD_ARR_LENGHT;

		/* Successor to close first endpoint of pipe, so only secpond one remains avail. for writing */
		close(input_pipe[0]);
#if defined(OUT_PIPE)
		close(output_pipe[0]);
#endif /* OUT_PIPE */

		ProcessCmds(pCmdChain);

		/* After all, close successors pipe, too */
		close(input_pipe[1]);
#if defined(OUT_PIPE)
		close(output_pipe[1]);
#endif /* OUT_PIPE */
	}


	/* Processing error code of parent on return */
	if (g_iChildPID != 0)
	{
		printf(" Parent process (%d) returns <%d>  \n", g_iChildPID, iRet);

		/* Only parent is eligible to report retcode to caller */
		return iRet;
	}
	/* Finalizing child without error code processing */
	else
	{
		printf(" Child process (%d) exits, does not return to caller  \n", g_iChildPID);
		
		/* Successor exits */
		exit(FORK_EXITCODE);
	}
}

#if defined(OUT_PIPE)
int iOutput_Start(char *cpMrk, int iTMO) 
{
/* Return code to define whether the child process was launched */
int iRet = FORK_UNDEFINED;

	/* Assign initial value */
	g_iChildPID = -1;

	g_iChildPID = fork();

	printf("New pid=%d \n", g_iChildPID);

	/* Parent process */
	if ( 0 < g_iChildPID ) 
	{
		/* Parent should not undertake anny activity in this position */
	}

	/* Child process */
	else if (0 == g_iChildPID)
	{
	int iChld = CMD_ARR_LENGHT;

		/* Successor to close first endpoint of pipe, so only secpond one remains avail. for writing */
		close(output_pipe[0]);

		while (1)
		{
		CMD_TYPE cResponceData;

			read(output_pipe[1], cResponceData, SINGLE_CMD_MAXLENGHT);
#if defined(_DBG)
			printf(">>>>RSPNC>>>> %s <<<<<", cResponceData);
#endif /* 0 */
		}

		/* After all, close successors pipe, too */
		close(output_pipe[1]);
	}


	/* Processing error code of parent on return */
	if (g_iChildPID != 0)
	{
		printf(" Parent process (%d) returns <%d>  \n", g_iChildPID, iRet);

		/* Only parent is eligible to report retcode to caller */
		return iRet;
	}
	/* Finalizing child without error code processing */
	else
	{
		printf(" Child process (%d) exits, does not return to caller  \n", g_iChildPID);
		
		/* Successor exits */
		exit(FORK_EXITCODE);
	}
}
#endif /* OUT_PIPE */

static int auth_callback(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata)
{
(void) verify;
(void) userdata;

	return ssh_getpass(prompt, buf, len, echo, verify);
}

struct ssh_callbacks_struct cb =
{
	.auth_function=auth_callback,
	.userdata=NULL
};

static void add_cmd(char *cmd)
{
int n;

	for (n = 0; (n < MAXCMD) && cmds[n] != NULL; n++);

	if (MAXCMD == n)
	{
		return;
	}

	cmds[n]=strdup(cmd);
}

static void usage()
{
	fprintf(stderr,"Usage : ssh(v.%s)  \n"
	"access_srv <HOST_IP> -l <USER>\n",
	ssh_version(0) );

	exit(0);
}

static int opts(int argc, char **argv)
{
FILE* fp = NULL;

	if(optind < argc)

		host=argv[optind++];

	if(host==NULL)

		usage();

	/* Try to open file with commands  */
	if ( NULL == (fp = fopen (DATA_FNAME, "r") ) )
	{
		printf("[%s] %s: can't open file <%s> \n", __FILE__, __func__ , DATA_FNAME);

		return FO_ERROR;
	}


	/* For each string of Raw Data file */
	while ( ! (feof (fp) ) ) 
	{
		/* Scan whole string into temp. buffer */
		if (NULL == fgets (cCmdDataBuf, SINGLE_CMD_MAXLENGHT, fp) )
		{
			/* no string read from data file */
		}
		else
		{
			printf("[%s] %s: scanned:%s", __FILE__, __func__, cCmdDataBuf);

			/* Attach just scanned data */
			EnrollCmd(&pCmdChain, cCmdDataBuf);
		}
	}


	/* Close file, and dispose pointer to Raw Data file */
	fclose(fp);

	return 0;
}




static void do_cleanup(int i)
{
/* unused variable */
(void) i;

	tcsetattr(0, TCSANOW, &terminal);
}

static void do_exit(int i)
{
/* unused variable */
(void) i;

	do_cleanup(0);

	exit(0);
}

ssh_channel chan;

int signal_delayed=0;

static void sigwindowchanged(int i)
{
(void) i;

	signal_delayed=1;
}

static void setsignal(void)
{
    signal(SIGWINCH, sigwindowchanged);

    signal_delayed=0;
}

static void sizechanged(void)
{
	struct winsize win = { 0, 0, 0, 0 };

	ioctl(1, TIOCGWINSZ, &win);

	ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);

	setsignal();
}

static void select_loop(ssh_session session,ssh_channel channel)
{
ssh_connector connector_in, connector_out, connector_err;

	ssh_event event = ssh_event_new();

	/* stdin */
	connector_in = ssh_connector_new(session);
	ssh_connector_set_out_channel(connector_in, channel, SSH_CONNECTOR_STDOUT);
	/* Attach first endpointg of input pipe to SSH core */
	ssh_connector_set_in_fd(connector_in, input_pipe[0] /* 0 */);
	ssh_event_add_connector(event, connector_in);

	/* stdout */
	connector_out = ssh_connector_new(session);
#if defined(OUT_PIPE)
	/* Attach first endpointg of output pipe to SSH core */
	ssh_connector_set_out_fd(connector_out,  output_pipe[0] /* 1*/);
#else
	ssh_connector_set_out_fd(connector_out,  1);
#endif /* OUT_PIPE */
	ssh_connector_set_in_channel(connector_out, channel, SSH_CONNECTOR_STDOUT);
	ssh_event_add_connector(event, connector_out);

	/* stderr */
	connector_err = ssh_connector_new(session);
	ssh_connector_set_out_fd(connector_err, 2);
	ssh_connector_set_in_channel(connector_err, channel, SSH_CONNECTOR_STDERR);
	ssh_event_add_connector(event, connector_err);

	while(ssh_channel_is_open(channel))
	{
		if(signal_delayed)

		    sizechanged();

		ssh_event_dopoll(event, 60000);
	}

	ssh_event_remove_connector(event, connector_in);
	ssh_event_remove_connector(event, connector_out);
	ssh_event_remove_connector(event, connector_err);

	ssh_connector_free(connector_in);
	ssh_connector_free(connector_out);
	ssh_connector_free(connector_err);

	ssh_event_free(event);
	ssh_channel_free(channel);
}

static void shell(ssh_session session)
{
ssh_channel channel;

struct termios terminal_local;

int interactive=isatty(0);

	channel = ssh_channel_new(session);

	if(interactive)
	{
		tcgetattr(0,&terminal_local);

		memcpy(&terminal, &terminal_local, sizeof(struct termios));
	}

	if(ssh_channel_open_session(channel))
	{
		printf("error opening channel : %s\n", ssh_get_error(session));

		return;
	}

	chan=channel;

	if(interactive)
	{
		ssh_channel_request_pty(channel);

		sizechanged();
	}

	if(ssh_channel_request_shell(channel))
	{
		printf("Requesting shell : %s\n",ssh_get_error(session));

		return;
	}

	if(interactive)
	{
		cfmakeraw(&terminal_local);

		tcsetattr(0,TCSANOW,&terminal_local);

		setsignal();
	}

	signal(SIGTERM,do_cleanup);

	select_loop(session,channel);

	if(interactive)

		do_cleanup(0);
}

static int client(ssh_session session)
{
int auth=0;
int state;

	if (user)

		if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)

			return -1;

	if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0)

		return -1;

	if (proxycommand != NULL)
	{
		if(ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, proxycommand))

		return -1;
	}

	ssh_options_parse_config(session, NULL);

	if(ssh_connect(session))
	{
		fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));

		return -1;
	}

	state=verify_knownhost(session);

	if (state != 0)

		return -1;

	ssh_userauth_none(session, NULL);

	auth=authenticate_console(session);

	if(auth != SSH_AUTH_SUCCESS)
	{
		return -1;
	}

	shell(session);

	return 0;
}

int main(int argc, char **argv)
{
ssh_session session;

	session = ssh_new();

	ssh_callbacks_init(&cb);

	ssh_set_callbacks(session,&cb);

	if(ssh_options_getopt(session, &argc, argv))
	{
		fprintf(stderr, "error parsing command line :%s\n", ssh_get_error(session) );

		usage();
	}

	opts(argc,argv);

	signal(SIGTERM, do_exit);

	/* Create input pipe between two endpoints */
	pipe(input_pipe);

#if defined(OUT_PIPE)
	/* Create output pipe between two endpoints */
	pipe(output_pipe);
#endif /* OUT_PIPE */

	/* Launch Successor to push commands into tray */
	iInput_Start("none", 25);

#if defined(OUT_PIPE)
//	iOutput_Start("", 25);
#endif /* OUT_PIPE */

	client(session);

	ssh_disconnect(session);

	ssh_free(session);

	ssh_finalize();

	/* Free memory occupied by dynamically stored raw data */
	DeleteCmds(&pCmdChain);

	return 0;
}
