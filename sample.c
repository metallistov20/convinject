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



#if (SAFE_TC_FORK)
/* Initiate process of running program 'program' not longer than 'iTMO' seconds, with 'in'/'out' piped redirected */
int iTimeCritical_Launch(char *program, int in, int out, int iTMO);
/* Start a program 'program' and stop it after 'iTMO' seconds, with 'in'/'out' piped redirected */
int iTimeCritical_Proceed(char *program, int in, int out, int iTMO);
#else
/* Initiate process of running program 'program' not longer than 'iTMO' seconds */
int iTimeCritical_Launch(char *program, int iTMO);
/* Start a program 'program' and stop it after 'iTMO' seconds */
int iTimeCritical_Proceed(char *program, int iTMO);
#endif /* (SAFE_TC_FORK) */

#if (SAFE_TC_FORK)
/* Initiate process of running program 'program' not longer than 'iTMO' seconds, with 'in'/'out' piped redirected */
int iTimeCritical_Start(char *program, int in, int out, int iTMO);
#else
/* Initiate process of running program 'program' not longer than 'iTMO' seconds */
int iTimeCritical_Start(char *program, int iTMO);
#endif /* (SAFE_TC_FORK) */

/* Stop a program 'program' in 'iTMO' seconds  in Linux way  */
int iTimeCritical_Stop();




/* Son process has terminated itself correcly */
#define FORK_SUCCESS 		(0)
/* Not defined condition of forked process(es) */
#define FORK_UNDEFINED 		(-1)
/* Son process was not launched*/
#define FORK_ERR_SON		(-8)
/* Grandson process was not launched */
#define FORK_ERR_GRANDSON	(-9)
/* Signal hasn't been set */
#define SIG_NOT_SET		(-11)
/* Code for exiting from forked process */
#define FORK_EXITCODE		(99)

/* 100 ms supposed to be enough to let the process to appear in the 'proc fs'. TODO: verify if does suffice */
#define PROCFS_REG_TIME 	100000
/* Process is visible as launched one in 'proc fs' filesystem */
#define PROCFS_REG_SUCCESS	(FORK_SUCCESS)
/* How much seconds to wait between commands */
#define BETW_CMD_TMO		2
/* Max length of command */
#define SINGLE_CMD_MAXLENGHT	256
/* Amount of comands in array */
#define CMD_ARR_LENGHT		8
/* Type of command */
typedef char CMD_TYPE[SINGLE_CMD_MAXLENGHT];
/* Array with commands, a.k.a. commad tray */
CMD_TYPE cCmdData[CMD_ARR_LENGHT];



/* Name of process to terminate on timeout */
static int g_iChildPID;

/* Pipe to maintain communication between parent and child */
int fd[2];


/********************************************************************
* int iTimeCritical_Start(char *program, int in, int out, int iTMO) - callback to launch
* program 'cpPrg' from witin forked process and then to terminate after 'iTMO'.

* Parameters:
*	'cpPrg' - program to be executed in interpreter
*	'iTMO' - amount of seconds to wait before forced termination of 'cpPrg'
*	'int in' - input pipe
*	'int out' - output pipe
*/
int iTimeCritical_Start(char *cpPrg, int iTMO) 
{
/* Return code to define whether the child process was launched */
int iRet = FORK_UNDEFINED;

	/* Initialize command tray <cCmdData> with (quasi)effective commands */
	strcpy(cCmdData[0], "show port isolation");
	strcpy(cCmdData[1], "history");
	strcpy(cCmdData[2], "ping 192.168.1.1");
	strcpy(cCmdData[3], "tracert 192.168.1.1");
	strcpy(cCmdData[4], "ping 127.0.0.1");
	strcpy(cCmdData[5], "tracert 127.0.0.1");
	strcpy(cCmdData[6], "history");
	strcpy(cCmdData[7], "exit");

	/* Assign initial value */
	g_iChildPID = -1;

	/* Set disposition of SIGALRM signal to 'iTimeCritical_Stop' handler */
	if ( SIG_ERR == signal(SIGALRM,(void (*)())iTimeCritical_Stop) )
	{
		printf("Signal has not been set. Will not do the effective pipe work\n");

		/* If can't signal an ALARM to a child process then don't launch it at all */
		return SIG_NOT_SET;
	}
	else
	{
		printf("SIGALARM has been assigned to handler <iTimeCritical_Stop>\n");
	}

	g_iChildPID = fork();

	printf("New pid=%d \n", g_iChildPID);

	/* Parent process */
	if ( 0 < g_iChildPID ) 
	{
		/* Successfully forked */
		iRet = FORK_SUCCESS;

		/* Issue SIGALARM to caller in 'iTMO' seconds*/
		alarm(iTMO);

		/* Wait to change state in a child */
		wait(NULL);

	}
	/* Child process */
	else if (0 == g_iChildPID)
	{
	int iChld = CMD_ARR_LENGHT;

		/* Successor to close first endpoint of pipe, so only secpond one remains avail. for writing */
		close(fd[0]);

		/* Add effective code here */
		while (iChld--)
		{
			/* Wait between commands */
			sleep (BETW_CMD_TMO);

			/* Push next command from tray into second endpoint of pipe */
			write(fd[1], cCmdData[(CMD_ARR_LENGHT-1) - iChld], strlen (cCmdData[(CMD_ARR_LENGHT-1) - iChld]) +  1);
		}

		/* After all, close sucessors pipe, too */
		close(fd[1]);
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

/********************************************************************
* int iTimeCritical_Stop(int iSignum) - handler called on arrival of SIGALARM.
* 
* Parameters:	none
*/
int iTimeCritical_Stop() 
{
	printf ("TERMINATION ON TMO\n");

	/* Send <exit> */
	write(fd[1], cCmdData[CMD_ARR_LENGHT-1], strlen (cCmdData[CMD_ARR_LENGHT-1]) +  1);

	/* And precardeously close both entries in pipe */
	//close(fd[0]); 
	close(fd[1]); 

	/* Linux way: terminate forked process <g_iChildPID> and its successor <g_cpChildName> */
	kill(g_iChildPID, SIGTERM);
}


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

	if (n == MAXCMD)
	{
		return;
	}

	cmds[n]=strdup(cmd);
}

static void usage()
{
	fprintf(stderr,"Usage : ssh [options] [login@]hostname\n"
	"sample client - libssh-%s\n"
	"Options :\n"
	"  -l user : log in as user\n"
	"  -p port : connect to port\n"
	"  -d : use DSS to verify host public key\n"
	"  -r : use RSA to verify host public key\n"
#ifdef WITH_PCAP
	"  -P file : create a pcap debugging file\n"
#endif
#ifndef _WIN32
	"  -T proxycommand : command to execute as a socket proxy\n"
#endif
	, ssh_version(0));

	exit(0);
}

static int opts(int argc, char **argv)
{
int i;

	/* insert your own arguments here */
	while((i=getopt(argc,argv,"T:P:"))!=-1)
	{
		switch(i)
		{
			case 'P':
				pcap_file=optarg;
			break;
#ifndef _WIN32
			case 'T':
				proxycommand=optarg;
			break;
#endif
			default:
				fprintf(stderr,"unknown option %c\n",optopt);

				usage();
		}
	}

	if(optind < argc)

		host=argv[optind++];

	while(optind < argc)

		add_cmd(argv[optind++]);

	if(host==NULL)

		usage();

	return 0;
}

#ifndef HAVE_CFMAKERAW
static void cfmakeraw(struct termios *termios_p)
{
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);

    termios_p->c_oflag &= ~OPOST;

    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);

    termios_p->c_cflag &= ~(CSIZE|PARENB);

    termios_p->c_cflag |= CS8;
}
#endif


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
	/* Attach first endpointg of pipe to SSH core */
	ssh_connector_set_in_fd(connector_in, fd[0] /* 0 */);
	ssh_event_add_connector(event, connector_in);

	/* stdout */
	connector_out = ssh_connector_new(session);
	ssh_connector_set_out_fd(connector_out, 1);
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

static void batch_shell(ssh_session session)
{
ssh_channel channel;

char buffer[1024];

int i,s=0;

	for( i=0; i<MAXCMD && cmds[i]; ++i)
	{
		s += snprintf(buffer+s,sizeof(buffer)-s,"%s ",cmds[i]);

		free(cmds[i]);

		cmds[i] = NULL;
	}


	channel=ssh_channel_new(session);

	ssh_channel_open_session(channel);


	if(ssh_channel_request_exec(channel,buffer))
	{
		printf("error executing \"%s\" : %s\n", buffer, ssh_get_error(session) );

		return;
	}

	select_loop(session,channel);
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

	if(!cmds[0])
	{
printf("[%s][%s]: SHELL session=<%p>\n", __FILE__, __func__, session);//+++
		shell(session);
	}
	else
	{
printf("[%s][%s]: BATCH_SHELL session=<%p>\n", __FILE__, __func__, session);//+++
		batch_shell(session);
	}
	return 0;
}

ssh_pcap_file pcap;

void set_pcap(ssh_session session);

void set_pcap(ssh_session session)
{
	if(!pcap_file)

		return;

	pcap=ssh_pcap_file_new();

	if(!pcap)

		return;

	if(ssh_pcap_file_open(pcap,pcap_file) == SSH_ERROR)
	{
		printf("Error opening pcap file\n");

		ssh_pcap_file_free(pcap);

		pcap=NULL;

		return;
	}

	ssh_set_pcap_file(session,pcap);
}

void cleanup_pcap(void);

void cleanup_pcap()
{
	if(pcap)
		ssh_pcap_file_free(pcap);

	pcap=NULL;
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

	set_pcap(session);

	/* Create Pipe between two endpoints */
	pipe(fd);

	/* Launch Successor to push commands into tray */
	iTimeCritical_Start("none", 25);

	client(session);

	ssh_disconnect(session);

	ssh_free(session);

	cleanup_pcap();

	ssh_finalize();

	return 0;
}
