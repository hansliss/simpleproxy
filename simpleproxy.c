/*
 * $Id$
 * ---------------------------------------------------------------------
 *
 * Simple proxy daemon
 * ====================
 *
 * Forked, cleaned up, simplified and re-indented by Hans@Liss.pp.se.
 * Reworked tracing to produce date-stamped trace files with client IP and port.
 * Removed HTTP and POP3 support as well as eight-bit stripping.
 *
 * Apart from my changes, all credit should go to the original authors.
 *
 * Original Authors:
 * --------
 * Vadim Zaliva    <lord@crocodile.org>
 * Vlad  Karpinsky <vlad@noir.crocodile.org>
 * Vadim Tymchenko <verylong@noir.crocodile.org>
 * Renzo Davoli <renzo@cs.unibo.it> (html probe & html basic authentication).
 *
 * Licence:
 * --------
 *
 * Copyright (C) 1999 Vadim Zaliva
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* #define DEBUG 1 */
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <sys/socket.h>
#ifndef _WIN32
# include <sys/un.h>
#endif
#include <sys/uio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdarg.h>
#if HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#if HAVE_STROPTS_H
# include <stropts.h>
#endif
#include <sys/stat.h>

#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include <netdb.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_TERMIO_H
# include <termio.h>
#endif
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netdb.h>

#include <time.h>

#include "cfg.h"

#ifndef SAME
# define SAME 0
#endif

#define MBUFSIZ 8192

#define SELECT_TIMOEOUT_SEC  5
#define SELECT_TIMOEOUT_MSEC 0

typedef struct sessionInfo_s {
  char client_name[256];
  uint16_t client_port;
  struct tm *startTime;
} *sessionInfo;

static char *SIMPLEPROXY_VERSION = "simpleproxy v3.5-HL by hans@liss.pp.se, forked from simpleproxy by lord@crocodile.org,vlad@noir.crocodile.org,verylong@noir.crocodile.org,renzo@cs.unibo.it";
static char *SIMPLEPROXY_USAGE   = "simpleproxy [-V] [-v] [-d] [-h] -L <[host:]port> -R <host:port> [-p PID file] [-t tracefile] [-T] [-f cfgfile]";

struct lst_record {
  char *s;
  struct lst_record *next;
};

static void daemon_start(void);
static int  writen(int fd, char *ptr, int nbytes);
static void pass_all(int client, int server, sessionInfo si);
static int  copy_data(int in, int out, int fromClient, sessionInfo si);
static int  get_hostaddr(const char *name);
static int  readln(int fd, char *buf, int siz, int fromClient, sessionInfo si);
static void child_dead( int stat );
static void write_pid( char* filename );
static int  open_remote(const char *rhost, int rportn);
static void logopen(void);
static void logclose(void);
static void logmsg(int, char *format, ...);
static void ctrlc(int);
static int  str2bool(char *s);
static void parse_host_port(const char *src, char **h_ptr, int *p_ptr);
static void replace_string(char **dst, const char*src);
static void fatal();
static void trace(int fd, char *buf, int siz, int fromClient, sessionInfo si);

static int   isVerbose          = 0;
static int   isDaemon           = 0;

static char *Tracefile          = NULL;
static int  isDailyTraceFile = 0;

static int SockFD    = -1;
static int SrcSockFD = -1;
static int DstSockFD = -1;

int main(int ac, char **av) {
  socklen_t    clien;
  struct sockaddr_in cli_addr, serv_addr;
  int    lportn = -1, rportn = -1;
  char  *lhost = NULL, *rhost = NULL;
  struct sessionInfo_s si;
  extern char *optarg;
  int    c;
  int    errflg = 0;
  char  *cfgfile = NULL;
  static struct Cfg *cfg = NULL;
  char  *pidfile = NULL;
  int    rsp = 1;
  
  /* Check for the arguments, and overwrite values from cfg file */
  while((c = getopt(ac, av, "VvdhL:R:p:t:Tf:")) != -1) {
    switch (c) {
    case 'V':
      fprintf(stderr, "%s\n", SIMPLEPROXY_VERSION);
      exit(0);
    case 'v':
      isVerbose++;
      break;
    case 'd':
      isDaemon++;
      break;
    case 'h':
      errflg++; // to make it print 'Usage:...'
      break;
    case 'L':
      parse_host_port(optarg, &lhost, &lportn);
      break;
    case 'R':
      parse_host_port(optarg, &rhost, &rportn);
      break;
    case 'p':
      replace_string(&pidfile, optarg);
      break;
    case 't':
      replace_string(&Tracefile, optarg);
      break;
    case 'T':
      isDailyTraceFile = 1;
      break;
    case 'f':
      replace_string(&cfgfile, optarg);
      if(cfgfile) {
	if(!(cfg=readcfg(cfgfile))){
	  logmsg(LOG_ERR,"Error reading cfg file.");
	  return 1;
	} else {
	  char *tmp;
	  /* let's process cfg file. Will cnage options only if they were not set already*/
	  if (!isVerbose) {
	    isVerbose = str2bool(cfgfind("Verbose", cfg, 0));
	  }
	  if (!isDaemon) {
	    isDaemon = str2bool(cfgfind("Daemon", cfg, 0));
	  }
	  tmp = cfgfind("LocalPort", cfg, 0);
	  if (tmp && lportn == -1) {
	    parse_host_port(tmp, NULL, &lportn);
	  }
	  tmp = cfgfind("RemotePort", cfg, 0);
	  if (tmp && rportn == -1) {
	    parse_host_port(tmp, NULL, &rportn);
	  }
	  tmp = cfgfind("LocalHost", cfg, 0);
	  if(tmp && !rhost) {
	    parse_host_port(tmp, &lhost, &lportn);
	  }
	  tmp = cfgfind("RemoteHost", cfg, 0);
	  if(tmp && !rhost) {
	    parse_host_port(tmp, &rhost, &rportn);
	  }
	  tmp = cfgfind("PIDFile", cfg, 0);
	  if(tmp && !pidfile) {
	    replace_string(&pidfile, tmp);
	  }
	  tmp = cfgfind("TraceFile", cfg, 0);
	  if(tmp && !Tracefile) {
	    replace_string(&Tracefile, tmp);
	  }
	  if (!isDailyTraceFile) {
	    isDailyTraceFile = str2bool(cfgfind("isDailyTraceFile", cfg, 0));
	  }
	  freecfg(cfg);
	}
      }
      break;
    default:
      errflg++;
    }

  }
  /* let us check options compatibility and completness*/
  if (!rhost || rportn <= 0 || lportn <= 0) {
    errflg++;
  }
  
  /* Do some options post-processing */
  
  if(errflg) {
    (void)fprintf(stderr, "%s\n", SIMPLEPROXY_VERSION);
    (void)fprintf(stderr, "Usage:\n\t%s\n", SIMPLEPROXY_USAGE);
    exit(1);
  }
  
  logopen();
  
  if(signal(SIGINT,ctrlc)==SIG_ERR) {
    logmsg(LOG_ERR,"Error installing interrupt handler.");
  }
  
  if(lportn <= 1024 && geteuid()!=0) {
    if(!isVerbose) {
      logopen();
      isVerbose++;
    }
    logmsg(LOG_ERR,"You must be root to run SIMPLEPROXY on reserved port");
    fatal();
  }
  
  /* Let's become a daemon */
  if(isDaemon) {
    daemon_start();
  }
  
  if(pidfile) {
    write_pid(pidfile);
  }
  
  if((SockFD = socket(AF_INET,SOCK_STREAM,0)) < 0) {
    logmsg(LOG_ERR,"Error creating socket.");
    fatal();
  }
  
  memset((void *)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = ((lhost && *lhost)? get_hostaddr(lhost): htonl(INADDR_ANY));
  serv_addr.sin_port = htons(lportn);
  
  if (setsockopt(SockFD, SOL_SOCKET, SO_REUSEADDR, (void*)&rsp, sizeof(rsp))) {
    logmsg(LOG_ERR,"Error setting socket options");
  }
  
  if (bind(SockFD, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    logmsg(LOG_ERR,"Error binding socket.");
    fatal();
  }
  
  logmsg(LOG_INFO,"Waiting for connections.");
  
  if (listen(SockFD,5) < 0) {
    logmsg(LOG_ERR,"Error listening socket: %s", strerror(errno));
    fatal();
  }
  
  while (1) {
    clien = sizeof(cli_addr);
	
    SrcSockFD = accept(SockFD,(struct sockaddr *)&cli_addr, &clien);
	
    if(SrcSockFD < 0) {
      if (errno == EINTR || errno == ECHILD) { /* Interrupt after SIGCHLD */
	continue;
      }
      logmsg(LOG_ERR, "accept error - %s", strerror(errno));
      fatal();
    }

    signal(SIGCHLD, child_dead);
	
    switch (fork()) {
    case -1: /* fork error */
      logmsg(LOG_ERR,"fork error - %s", strerror(errno));
      break;
	  
    case 0: /* Child */
      strncpy(si.client_name, inet_ntoa(cli_addr.sin_addr), sizeof(si.client_name));
      si.client_name[sizeof(si.client_name)-1] = '\0';
      si.client_port = ntohs(cli_addr.sin_port);
      time_t now_t = time(NULL);
      si.startTime = localtime(&now_t);
	  
      /*
       * I don't know is that a bug, but on Irix 6.2 parent
       * process will not be able to accept any new connection
       * if SockFD is closed here.                  Vlad
       */
	  
      /* (void)shutdown(SockFD,2); */
      /* (void)close(SockFD);      */
	  
      /* Process connection */
	  
      logmsg(LOG_NOTICE, "Connect from %s:%d", si.client_name, si.client_port);
	  
      DstSockFD = open_remote(rhost, rportn);

      if (DstSockFD == -1)
        fatal();

      pass_all(SrcSockFD, DstSockFD, &si);

      logmsg(LOG_NOTICE, "Connection from %s:%d closed", si.client_name, si.client_port);
	  

      shutdown(DstSockFD, 2);
      close(DstSockFD);
      DstSockFD = -1;

      shutdown(SrcSockFD, 2);
      close(SrcSockFD);
      SrcSockFD = -1;
      closelog();
      return 0; // Exit
    default:
      /* Parent */
      close(SrcSockFD);
      SrcSockFD = -1;
    }
  }
  return 0;
}

/*
 * Write "n" bytes to a descriptor.
 * Use in place of write() when fd is a stream socket.
 */
static int writen(int fd, char *ptr, int nbytes) {
  int nleft, nwritten;

  nleft = nbytes;
  while (nleft > 0) {
    nwritten = write(fd, ptr, nleft);
    if(nwritten <= 0) {
      return(nwritten); /* error */
    }

    nleft -= nwritten;
    ptr   += nwritten;
  }
  return(nbytes - nleft);
}

/*
 * Detach a daemon process from login session context.
 */
static void daemon_start(void) {
  /* Maybe I should do 2 forks here? */

  if(fork()) {
    exit(0);
  }
  if (chdir("/")) {}
  umask(0);
  (void) close(0);
  (void) close(1);
  (void) close(2);
  (void) open("/", O_RDONLY);
  (void) dup2(0, 1);
  (void) dup2(0, 2);
  setsid();
}


void pass_all(int client, int server, sessionInfo si) {
  fd_set         in;
  struct timeval tv;
  int            nsock, retval;

  nsock = ((server > client)? server: client) + 1;
  
  while(1) {
    FD_ZERO(&in);
    FD_SET(server, &in);
    FD_SET(client, &in);
	
    tv.tv_sec  = SELECT_TIMOEOUT_SEC;
    tv.tv_usec = SELECT_TIMOEOUT_MSEC;
	
    retval = select(nsock, &in, NULL, NULL, &tv);
	
    switch (retval) {
    case  0 :
      /* Nothing to receive */
      break;
    case -1:
      /* Error occured */
      logmsg(LOG_ERR, "i/o error - %s", strerror(errno));
      return;
    default:
      if(FD_ISSET(server, &in)) {
	retval = copy_data(server, client, 0, si);
      } else if(FD_ISSET(client, &in)) {
	retval = copy_data(client, server, 1, si);
      } else {
	retval = -1;
      }
      if( retval < 0) {
	return;
      }
    }
  }
}

static int get_hostaddr(const char *name) {
  struct hostent *he;
  int             res = -1;
  int             a1,a2,a3,a4;
  
  if (sscanf(name,"%d.%d.%d.%d",&a1,&a2,&a3,&a4) == 4)
    res = inet_addr(name);
  else {
    he = gethostbyname(name);
    if (he)
      memcpy(&res , he->h_addr , he->h_length);
  }
  return res;
}

static int copy_data(int in, int out, int fromClient, sessionInfo si) {
  int nread;
  static char *buff=NULL;
  static int size=0;
  static int len=0;

  if ((size - len) == 0) {
    if (size==0) size=MBUFSIZ;
    else size *= 2;
    buff = realloc(buff,size+1);
    if (!buff) {
      return -1;
    }
  }

  if ((nread = readln(in, buff+len, size-len, fromClient, si)) <= 0) {
    return -1;
  } else {
    len += nread;
    buff[len]=0;
    /* printf("R %d %d ==%s==\n",nread,len,buff); */

    if(writen(out, buff, len) != len) {
      logmsg(LOG_ERR,"write error");
      return -1;
    }
    len -= nread;
    *buff=0;
  }
  return 0;
}

void child_dead(int stat) {
  while(waitpid( -1, NULL, WNOHANG ) > 0);
  signal( SIGCHLD, child_dead );
}

void parse_host_port(const char *src, char ** h_ptr, int *p_ptr) {
  if(src) {
    struct servent *se;
    /* Look for ':' separator */
    const char *tmp = strrchr(src, ':');

    if (tmp) {
      if (h_ptr) {
	replace_string(h_ptr, src);

	/* This looks like host:port syntax */
		
	*((*h_ptr) + (tmp - src)) = '\0';
      }
      tmp++;
    } else {
      tmp = src; /* to compensate future ++; */
    }

    *p_ptr = (isdigit(*tmp))?atoi(tmp):((!(se = getservbyname(tmp, "tcp")))?-1:ntohs(se->s_port));
  }
}

void write_pid( char* filename ) {
  FILE *f;

  if(!(f=fopen(filename,"w"))) {
    logmsg(LOG_WARNING,"Can't open file '%s' to write PID",filename);
    return;
  }

  fprintf(f,"%d",getpid());
  fclose(f);
  return;
}



static int readln(int fd, char *buf, int siz, int fromClient, sessionInfo si) {
  int  nread;

  nread = read(fd, buf, siz);
  if(nread <= 0) {
    if(nread < 0) {
      logmsg(LOG_ERR,"read error");
    }
    return -1;
  } else {
    if (Tracefile) {
      // do tracing;
      trace(fd, buf, nread, fromClient, si);
    }
    return nread;
  }
}



int open_remote(const char *rhost, int rportn) {
  const char        *dest_host;
  int                dest_port;
  struct sockaddr_in remote_addr;
  int                fd;


  dest_host = rhost;
  dest_port = rportn;

  if (!(dest_host && *dest_host))
    dest_host = "127.0.0.1";

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    logmsg(LOG_ERR,"Can't create socket - %s ", strerror(errno));
    return -1;
  }

  remote_addr.sin_family      = AF_INET;
  remote_addr.sin_port        = htons(dest_port);
  remote_addr.sin_addr.s_addr = get_hostaddr(dest_host);

  if (remote_addr.sin_addr.s_addr == -1) {
    logmsg(LOG_ERR,"Unknown host %s", dest_host);
    return -1;
  }

  if (connect(fd, (struct sockaddr *) &remote_addr, sizeof(remote_addr))) {
    logmsg(LOG_ERR,"connect error to %s:%d - %s", dest_host, dest_port, strerror(errno));
    return -1;
  }

  return fd;
}

static void logopen(void) {
  if(isVerbose & isDaemon) {
#if HAVE_OPENLOG
    openlog("simpleproxy", LOG_PID| LOG_CONS|LOG_NOWAIT, LOG_USER);
#else
    log(LOG_WARNING,"Compiled without syslog. Syslog can't be used.");
#endif
  }
}

static void logclose(void) {
  if(isVerbose && isDaemon) {
#if HAVE_CLOSELOG
    closelog();
#endif
  }
}

/**
 * This function should be used as central logging facility.
 * 'type' argument should be one of following:
 *
 *  LOG_EMERG   system is unusable
 *  LOG_ALERT   action must be taken immediately
 *  LOG_CRIT    critical conditions
 *  LOG_ERR error conditions
 *  LOG_WARNING warning conditions
 *  LOG_NOTICE  normal but significant condition
 *  LOG_INFO    informational
 *  LOG_DEBUG   debug-level messages
 */
static void logmsg(int type, char *format, ...) {
#ifndef DEBUG
  if(type==LOG_DEBUG) {
    return;
  }
#endif

  if(isVerbose) {
    va_list ap;
    va_start(ap, format);

    if(isDaemon) {
      char buffer[MBUFSIZ];

#if HAVE_VSNPRINTF
      (void)vsnprintf(buffer, MBUFSIZ, format, ap);
#else
# if HAVE_VSPRINTF
#  ifndef SGI
#   warning "Using VSPRINTF. Buffer overflow could happen!"
#  endif /* SGI */
      (void)vsprintf(buffer, format, ap);
# else
#  error "Your standard libabry have neither vsnprintf nor vsprintf defined. One of them is reqired!"
# endif
#endif
#if HAVE_SYSLOG
      syslog(type, "%s", buffer);
#endif
    } else {
      (void) fprintf(stderr, "simpleproxy[%d]:", (int)getpid());
      (void) vfprintf(stderr, format, ap);
      (void) fprintf(stderr, "\n");
    }
    va_end(ap);
  }
}

static void ctrlc(int s) {
  logmsg(LOG_INFO,"Interrupted... Shutting down connections");

  if(SockFD    !=-1) {
    /*  (void)shutdown(SockFD,2); */
    (void)close(SockFD   );
  }
  if(SrcSockFD !=-1) {
    /*  (void)shutdown(SrcSockFD,2); */
    close(SrcSockFD);
  }
  if(DstSockFD !=-1) {
    /*  (void)shutdown(DstSockFD,2); */
    close(DstSockFD );
  }

  /* system V style. */
  /*    if(signal(SIGINT,ctrlc)==SIG_ERR)
	logmsg(LOG_INFO,"Error installing interrupt handler."); */
  exit(1);
}

/**
 * Returns 1 if string could be interpreted as boolean TRUE in cfg.
 * otherwise returns 0.
 */
int str2bool(char *s) {
  if(!s) {
    return 0;
  } else {
    return !(strcasecmp(s,"yes") &&
	     strcasecmp(s,"true") &&
	     strcasecmp(s,"ok") &&
	     strcasecmp(s,"oui") &&
	     strcasecmp(s,"1")
	     );
  }
}

void replace_string(char **dst, const char *src) {
  if(dst) {
    if(*dst) {
      free(*dst);
    }
    *dst = (src)?strdup(src):NULL;
  }
}

void fatal() {
  if (SockFD != -1) {
    close(SockFD);
  }
  if (SrcSockFD != -1) {
    close(SrcSockFD);
  }
  if (DstSockFD != -1) {
    close(DstSockFD);
  }
  logclose();
  exit(1);
}

 
void trace(int fd, char *buf, int siz, int fromClient, sessionInfo si) {
  char trace_header[256];
  int trace_header_len;
  // underscore + date + underscore + time + underscore + ipaddr + underscore + port + NUL
  int buflen = strlen(Tracefile) + 1 + 8 /*+ 1 + 6 */+ 1 + 15 + 1 + 5 + 1;
  char *tfName = malloc(buflen);
  time_t now_t = time(NULL);
  struct tm *now = localtime(&now_t);
  ssize_t bytes_written;
  
  if (isDailyTraceFile) {
    snprintf(tfName, buflen,
	     //	     "%s_%04d%02d%02d_%02d%02d%02d_%s_%d",
	     "%s_%04d%02d%02d_%s_%d",
	     Tracefile,
	     now->tm_year + 1900,
	     now->tm_mon + 1,
	     now->tm_mday,
	     //	     si->startTime->tm_hour,
	     //	     si->startTime->tm_min,
	     //	     si->startTime->tm_sec,
	     si->client_name,
	     si->client_port);
  } else {
    strcpy(tfName, Tracefile);
  }
  int tfd = open(tfName, O_CREAT | O_WRONLY| O_APPEND, S_IRUSR | S_IWUSR |  S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  
  free(tfName);
  
  if(tfd < 0) {
    logmsg(LOG_ERR,"Tracing is disabled, can't create/open trace file - %s", strerror(errno));
    free(Tracefile);
    Tracefile = NULL;
  } else {
    trace_header_len = snprintf(trace_header, sizeof(trace_header) - 1,
				"\n##### %c %02d:%02d:%02d %d #####\n",
				fromClient?'>':'<',
				now->tm_hour,
				now->tm_min,
				now->tm_sec,
				siz);
    
    /* TODO: check actual return value and log error if needed */
    ssize_t bytes_to_write = (trace_header_len <= sizeof(trace_header) - 1)? trace_header_len: (sizeof(trace_header) - 1);
    if ((bytes_written = write(tfd, trace_header, bytes_to_write)) != bytes_to_write ||
	(bytes_written = write(tfd, buf, siz)) != siz) {
      fprintf(stderr, "trace(): short write\n");
    }
    close(tfd);
  }
}
