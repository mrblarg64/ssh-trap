//#define _XOPEN_SOURCE 500
//#define _GNU_SOURCE
//#define _DEFAULT_SOURCE

#include <stdio.h>
//#include <string.h>
#include <errno.h>
#include <stdlib.h>
//#include <string.h>
//#include <locale.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <pthread.h>
#include <grp.h>

#define RUN_AS_UID 65534
#define RUN_AS_GID 65534
#define RSA_KEY_FILE "/home/brian/ssh_key"
#define ECDSA_KEY_FILE "/home/brian/ssh_key_ecdsa"
#define LOG_FILE "/home/brian/st.log"
#define KEY_EXCHANGE_CONST_STR "rsa-sha2-512,rsa-sha2-256,ssh-rsa"
#define MAXIPSTRLEN 60
//#define PASS_FILE "st.pass"
//#define USER_FILE "st.user"
/* #define MAX_LINUX_SENDFILE 0x7ffff000 */
/* #define DENT_BUF_SIZE 512 */
/* #define MY_MAX_PATH 1024 */
struct thissess
{
	char ipstr[MAXIPSTRLEN];
	uint16_t port;
	unsigned long attempt;
};

int logfd;
const int ssopt = 1;

//struct ssh_server_callbacks_struct cb = {.userdata = NULL, .auth_password_function = a
//char path[MY_MAX_PATH] = {0};

/* void printusage() */
/* { */
/* 	puts("Usage:\n\tbcp source-directory target-directory\n\tcopies source-directory into target-directory\n\tdoesn't overwrite files that already exist"); */
/* 	return; */
/* } */

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

/* int passfunc(ssh_session ssess, const char *user, const char *pass, void *ud) */
/* { */
/* 	struct thissess *ts; */

/* 	(void) ssess; */
/* 	ts = ud; */

/* 	ts->attempt++; */
/* 	logipcreds(ts, user, pass); */
/* 	return SSH_AUTH_DENIED; */
/* } */

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

	if (setsockopt(curclifd, SOL_SOCKET, SO_KEEPALIVE, &ssopt, sizeof(int)) == -1)
	{
		logmsgip("setsockopt() failed, continuing...", &ts);
	}

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

/* static inline unsigned processfile(char *file) */
/* { */
	
/* } */

int main(int argc, char *argv[])
{
	pthread_attr_t pattr;
	ssh_bind sbind;
	ssh_session ssess;
	int pcreateretval;
	pthread_t nt;

	(void) argc;
	(void) argv;

	logfd = open(LOG_FILE, O_WRONLY | O_CREAT, 0644);
	if (logfd == -1)
	{
		//perror("open() log file");
		return 1;
	}
	if (lseek(logfd, 0, SEEK_END) == -1)
	{
		//perror("lseek() log file");
		return 1;
	}
	
	logmsg("starting up");

	sbind = ssh_bind_new();

	if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_RSAKEY, RSA_KEY_FILE) < 0)
	{
		logmsg("failed to ssh_bind_options_set() RSAKEY");
		return 1;
	}

	if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_ECDSAKEY, ECDSA_KEY_FILE) < 0)
	{
		logmsg("failed to ssh_bind_options_set() RSAKEY");
		return 1;
	}

	if (ssh_bind_listen(sbind) < 0)
	{
		logmsg("failed to ssh_bind_listen()");
		logmsg(ssh_get_error(sbind));
		return 1;
	}

	if (setgroups(0, NULL) != 0)
	{
		logmsg("setgroups() failed");
		return 1;
	}
	if (setgid(RUN_AS_GID))
	{
		//perror("setgid()");
		logmsg("failed to setgid()");
		return 1;
	}
	if (getgid() != RUN_AS_GID)
	{
		logmsg("getgid() returned an unexpected result");
		return 1;
	}
	if (setuid(RUN_AS_UID))
	{
		//perror("setuid()");
		logmsg("failed to setuid()");
		return 1;
	}
	if (getuid() != RUN_AS_UID)
	{
		logmsg("getuid() returned an unexpected result");
		return 1;
	}

	pthread_attr_init(&pattr);
	if (pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED))
	{
		logmsg("pthread_attr_setdetachstate() failed");
		return 1;
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
			pcreateretval = pthread_create(&nt, &pattr, conhandler, ssess);
			if ((pcreateretval) && (pcreateretval != EAGAIN))
			{
				logmsg("pthread_create() failed");
				return 1;
			}
		}
		while (pcreateretval);
	}
	return 0;
}
