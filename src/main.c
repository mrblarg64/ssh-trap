//Copyright (C) 2022-2024 Brian William Denton
//Available under the GNU GPLv3 License

//#define _XOPEN_SOURCE 500
//#define _GNU_SOURCE
//#define _DEFAULT_SOURCE

#define SSHTRAP_SET_KEEPIDLE
#ifdef SSHTRAP_SET_KEEPIDLE
#include <netinet/tcp.h>
int ssoptkidle = -1;
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>

#define CONFIG_FILE "/etc/ssh-trap/ssh-trap.conf"
#define NEWLINE_CHARS "\n\r"


#define WHITESPACE_CHARS " \t="
#define CONFIG_USERNAME "user"
#define CONFIG_LOGFILE "logfile"
#define CONFIG_RSAKEYFILE "rsakey"
#define CONFIG_ECDSAKEYFILE "ecdsakey"
#ifdef SSHTRAP_SET_KEEPIDLE
#define CONFIG_TCPKEEPIDLE "tcpkeepidle"
#endif
//#define KEY_EXCHANGE_CONST_STR "rsa-sha2-512,rsa-sha2-256,ssh-rsa"
#define MAXIPSTRLEN 60

struct thissess
{
	char ipstr[MAXIPSTRLEN];
	uint16_t port;
	unsigned long attempt;
};

int logfd;

uid_t runasuid;
gid_t runasgid;
char *logfilepath = NULL;
char *rsakeyfile = NULL;
char *ecdsakeyfile = NULL;

static inline void getipstring(struct sockaddr_storage *s, char *ipstring, uint16_t *port)
{
        //get ip string                                                                                                                                                 
        if (s->ss_family == AF_INET)
        {
                inet_ntop(AF_INET, &((struct sockaddr_in*)s)->sin_addr.s_addr, ipstring, MAXIPSTRLEN);
                #ifdef __ORDER_LITTLE_ENDIAN__
                *port = __builtin_bswap16(((struct sockaddr_in*)s)->sin_port);
                #else
                *port = ((struct sockaddr_in*)s)->sin_port;
                #endif
        }
        else
        {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)s)->sin6_addr.s6_addr, ipstring, MAXIPSTRLEN);
                #ifdef __ORDER_LITTLE_ENDIAN__
                *port = __builtin_bswap16(((struct sockaddr_in6*)s)->sin6_port);
                #else
                *port = ((struct sockaddr_in6*)s)->sin6_port;
                #endif
        }
        return;
}

static inline void logmsg(const char *msg)
{
	struct timespec curtime;
	struct tm tmcurtime;

	clock_gettime(CLOCK_REALTIME, &curtime);
	localtime_r(&curtime.tv_sec, &tmcurtime);

	dprintf(logfd, "[%i-%02i-%02i %02i:%02i:%02i.%03li] - %s\n", tmcurtime.tm_year + 1900, tmcurtime.tm_mon + 1, tmcurtime.tm_mday, tmcurtime.tm_hour, tmcurtime.tm_min, tmcurtime.tm_sec, curtime.tv_nsec/1000000, msg);
}

static inline void logmsgip(const char *msg, const struct thissess *c)
{
	struct timespec curtime;
	struct tm tmcurtime;

	clock_gettime(CLOCK_REALTIME, &curtime);
	localtime_r(&curtime.tv_sec, &tmcurtime);

	dprintf(logfd, "[%i-%02i-%02i %02i:%02i:%02i.%03li] - [%s %hu] - %s\n", tmcurtime.tm_year + 1900, tmcurtime.tm_mon + 1, tmcurtime.tm_mday, tmcurtime.tm_hour, tmcurtime.tm_min, tmcurtime.tm_sec, curtime.tv_nsec/1000000, c->ipstr, c->port, msg);
}

static inline void logipcreds(const struct thissess *c, const char *user, const char *pass)
{
	struct timespec curtime;
	struct tm tmcurtime;

	clock_gettime(CLOCK_REALTIME, &curtime);
	localtime_r(&curtime.tv_sec, &tmcurtime);

	dprintf(logfd, "[%i-%02i-%02i %02i:%02i:%02i.%03li] - [%s %hu] - login attempt %lu \"%s\" \"%s\"\n", tmcurtime.tm_year + 1900, tmcurtime.tm_mon + 1, tmcurtime.tm_mday, tmcurtime.tm_hour, tmcurtime.tm_min, tmcurtime.tm_sec, curtime.tv_nsec/1000000, c->ipstr, c->port, c->attempt, user, pass);
}

void *conhandler(void *arg)
{
	struct sockaddr_storage cliaddr;
	socklen_t cliaddrsize = sizeof(struct sockaddr_storage);
	ssh_session ssess;
	//struct ssh_server_callbacks_struct cb;
	struct thissess ts;
	//ssh_event eloop;
	//int dpretval;
	ssh_message message;
	int curclifd;

	ssess = arg;

	curclifd = ssh_get_fd(ssess);
	if (getpeername(curclifd, (struct sockaddr*) &cliaddr, &cliaddrsize) == -1)
	{
		logmsg("getpeername() failed");
		ssh_disconnect(ssess);
		ssh_free(ssess);
		return NULL;
	}
	

	getipstring(&cliaddr, ts.ipstr, &ts.port);

	logmsgip("new connection", &ts);

	ts.attempt = 0;

	if (ssh_handle_key_exchange(ssess))
	{
		logmsgip("key exchange failed", &ts);
		logmsgip(ssh_get_error(ssess), &ts);
		ssh_disconnect(ssess);
		ssh_free(ssess);
		return NULL;
	}
	while (1)
	{
		message = ssh_message_get(ssess);
		if (!message)
		{
			break;
		}
		switch (ssh_message_type(message))
		{
		case SSH_REQUEST_AUTH:
			switch (ssh_message_subtype(message))
			{
			case SSH_AUTH_METHOD_PASSWORD:
				ts.attempt++;
				logipcreds(&ts, ssh_message_auth_user(message), ssh_message_auth_password(message));
				ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
				ssh_message_reply_default(message);
				break;
			default:
				logmsgip("unavailable ssh_auth type requested", &ts);
				ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
				ssh_message_reply_default(message);
			}
			break;
		default:
			ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
			ssh_message_reply_default(message);
		}
		ssh_message_free(message);
	}

	ssh_disconnect(ssess);
	ssh_free(ssess);
	logmsgip("disconnect", &ts);
	return NULL;
}

static inline void loadconfig()
{
	int myerrno;
	int cfd;
	struct stat fst;
	struct passwd *u;
	char *finram;
	char *cursor;
	char *curline;
	char *curtok;
	char *toka;
	char *tokb;
	unsigned char founduser=0;
	#ifdef SSHTRAP_SET_KEEPIDLE
	char *endptr;
	unsigned char foundkeepidle=0;
	#endif

	cfd = open(CONFIG_FILE, O_RDONLY, 0);
	if (cfd == -1)
	{
		myerrno = errno;
		logmsg("config file failed open()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	if (fstat(cfd, &fst) == -1)
	{
		myerrno = errno;
		logmsg("config file failed fstat()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	finram = malloc(1 + fst.st_size);//+1 for null
	if (!finram)
	{
		myerrno = errno;
		logmsg("config file parse failed malloc()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	if (read(cfd, finram, fst.st_size) != fst.st_size)
	{
		myerrno = errno;
		logmsg("config file parse failed read()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	close(cfd);
	finram[fst.st_size] = 0;//null the end

	cursor = finram;
	while (cursor)
	{
		curline = strsep(&cursor, NEWLINE_CHARS);
		curtok = __builtin_strchr(curline, '#');
		if (curtok)
		{
			*curtok = 0;
		}
		if (!__builtin_strlen(curline))
		{
			continue;
		}
		
		curtok = curline;
		while (curtok)
		{
			toka = strsep(&curtok, WHITESPACE_CHARS);
			if (__builtin_strlen(toka))
			{
				break;
			}
		}
		if (!curtok)
		{
			logmsg("bad line in config file (debug info: no token a or only a)");
			exit(1);
		}
		while (curtok)
		{
			tokb = strsep(&curtok, WHITESPACE_CHARS);
			if (__builtin_strlen(tokb))
			{
				break;
			}
		}
		if (!__builtin_strlen(tokb))
		{
			logmsg("bad line in config file (debug info: no token b)");
			exit(1);
		}
		if (!__builtin_strcmp(CONFIG_USERNAME, toka))
		{
			//username
			if (founduser)
			{
				logmsg("config file parse error MULTIPLE USER DEFINITIONS!");
				exit(1);
			}
			errno = 0;
			u = getpwnam(tokb);
			if (!u)
			{
				myerrno = errno;
				logmsg("config file parse failed getpwnam()");
				if (myerrno)
				{
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("user probably does not exist");
				exit(1);
			}
			runasuid = u->pw_uid;
			runasgid = u->pw_gid;
			founduser = 1;
		}
		else if (!__builtin_strcmp(CONFIG_LOGFILE, toka))
		{
			//log file
			if (logfilepath)
			{
				logmsg("config file parse error MULTIPLE LOGFILE DEFINITIONS!");
				exit(1);
			}
			logfilepath = strdup(tokb);
			if (!logfilepath)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		else if (!__builtin_strcmp(CONFIG_RSAKEYFILE, toka))
		{
			//rsa key
			if (rsakeyfile)
			{
				logmsg("config file parse error MULTIPLE RSA KEYFILE DEFINITIONS!");
				exit(1);
			}
			rsakeyfile = strdup(tokb);
			if (!rsakeyfile)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		else if (!__builtin_strcmp(CONFIG_ECDSAKEYFILE, toka))
		{
			//ecdsa key
			if (ecdsakeyfile)
			{
				logmsg("config file parse error MULTIPLE ECDSA KEYFILE DEFINITIONS!");
				exit(1);
			}
			ecdsakeyfile = strdup(tokb);
			if (!rsakeyfile)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		#ifdef SSHTRAP_SET_KEEPIDLE
		else if (!__builtin_strcmp(CONFIG_TCPKEEPIDLE, toka))
		{
			if (foundkeepidle)
			{
				logmsg("config file parse error MULTIPLE TCPKEEPIDLE DEFINITIONS!");
				exit(1);
			}
			ssoptkidle = strtoumax(tokb, &endptr, 10);
			if ((*endptr) || (!ssoptkidle) || (ssoptkidle == ((int)UINTMAX_MAX)))
			{
				if (errno)
				{
					myerrno = errno;
					logmsg("config file parse failed strtoimax()");
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("invalid tcpkeepidle time");
				exit(1);
			}
		}
		#endif
		else
		{
			logmsg("encountered unknown line in config file, check that compile time support for options you want were enabled");
			exit(EINVAL);
		}
	}
	if (!(founduser && logfilepath && rsakeyfile && ecdsakeyfile))
	{
		logmsg("config file parse failed, missing definition. Verify all are present: user, logfile, rsakey, ecdsakey");
		exit(1);
	}

	free(finram);
}

int main(int argc, char *argv[])
{
	int myerrno;
	pthread_attr_t pattr;
	ssh_bind sbind;
	ssh_session ssess;
	pthread_t nt;
	int sock;
	struct sockaddr_storage listener;
	int ssopt;

	(void) argc;
	(void) argv;

	logfd = STDERR_FILENO;

	loadconfig();

	logfd = open(logfilepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (logfd == -1)
	{
		myerrno = errno;
		perror("log file open()");
		return myerrno;
	}
	free(logfilepath);
	
	logmsg("starting up");


	sbind = ssh_bind_new();

	if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_RSAKEY, rsakeyfile) < 0)
	{
		logmsg("failed to ssh_bind_options_set() RSAKEY");
		return 1;
	}
	free(rsakeyfile);

	if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_ECDSAKEY, ecdsakeyfile) < 0)
	{
		logmsg("failed to ssh_bind_options_set() ECDSAKEY");
		return 1;
	}
	free(ecdsakeyfile);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		myerrno = errno;
		logmsg("failed to socket()");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	//on linux-6.5.5. these are inhereted after accept()
	//also the kernel's broken rt_tos2priority() function will
	//be fine with the IPTOS_DSCP_LE so there is no need
	//to setsockopt(SO_PRIORITY) (btw priority IS NOT inhereted)
	ssopt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("SO_KEEPALIVE setsockopt() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	ssopt = IPTOS_DSCP_LE;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("IP_TOS (DSCP) setsockopt() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	#ifdef SSHTRAP_SET_KEEPIDLE
	if (ssoptkidle != -1)
	{
		if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &ssoptkidle, sizeof(int)) == -1)
		{
			myerrno = errno;
			logmsg("TCP_KEEPIDLE setsockopt() failed");
			logmsg(strerror(myerrno));
			return myerrno;
		}
	}
	#endif
	ssopt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("SO_REUSEADDR setsockopt() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}

		__builtin_memset(&listener, 0, sizeof(listener));
	((struct sockaddr_in*)&listener)->sin_family = AF_INET;
	((struct sockaddr_in*)&listener)->sin_addr.s_addr = 0;
	#ifdef __ORDER_LITTLE_ENDIAN__
	((struct sockaddr_in*)&listener)->sin_port = __builtin_bswap16(22);
	#else
	((struct sockaddr_in*)&listener)->sin_port = 22;
	#endif

	if (bind(sock, (struct sockaddr*) &listener, sizeof(struct sockaddr_storage)) == -1)
	{
		myerrno = errno;
		perror("bind()");
		return myerrno;
	}

	if (listen(sock, 1024) == -1)
	{
		myerrno = errno;
		perror("listen()");
		return myerrno;
	}

	ssh_bind_set_fd(sbind, sock);

	//if you look at the source for ssh_bind_listen()
	//you'll see that it doesn't bind() or listen()
	//if the fd is valid
	//but it does pull in the necessary key files
	//so we do this here before we change uid
	//(while we still have access to the keys)
	if (ssh_bind_listen(sbind) < 0)
	{
		logmsg("failed to ssh_bind_listen()");
		logmsg(ssh_get_error(sbind));
		return 1;
	}

	if (setgroups(0, NULL) != 0)
	{
		myerrno = errno;
		logmsg("setgroups() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	if (setgid(runasgid))
	{
		myerrno = errno;
		logmsg("failed to setgid()");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	if (getgid() != runasgid)
	{
		logmsg("getgid() returned an unexpected result");
		return 1;
	}
	if (setuid(runasuid))
	{
		myerrno = errno;
		logmsg("failed to setuid()");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	if (getuid() != runasuid)
	{
		logmsg("getuid() returned an unexpected result");
		return 1;
	}

	pthread_attr_init(&pattr);
	myerrno = pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
	if (myerrno)
	{
		logmsg("failed pthread_attr_setdetachstate()");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	logmsg("startup complete, entering accept loop");

	while (1)
	{
		ssess = ssh_new();		
		if (ssh_bind_accept(sbind, ssess) == SSH_ERROR)
		{
			logmsg("error accepting a connection");
			logmsg(ssh_get_error(sbind));
			return 1;
		}
		do
		{
			myerrno = pthread_create(&nt, &pattr, conhandler, ssess);
			if ((myerrno) && (myerrno != EAGAIN))
			{
				logmsg("failed pthread_create()");
				logmsg(strerror(myerrno));
				return myerrno;
			}
		}
		while (myerrno);
	}
	return 0;
}
