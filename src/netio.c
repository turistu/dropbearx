#include "netio.h"
#include "list.h"
#include "dbutil.h"
#include "session.h"
#include "debug.h"
#include "runopts.h"

struct dropbear_progress_connection {
	struct addrinfo *res;
	struct addrinfo *res_iter;

	char *remotehost, *remoteport; /* For error reporting */

	connect_callback cb;
	void *cb_data;

	struct Queue *writequeue; /* A queue of encrypted packets to send with TCP fastopen,
								or NULL. */

	int sock;

	char* errstring;
	char *bind_address, *bind_port;
	enum dropbear_prio prio;
};

union any_address {
	struct sockaddr sa;
	struct sockaddr_un su;
	struct sockaddr_in si;
	struct sockaddr_in6 si6;
};

/* Deallocate a progress connection. Removes from the pending list if iter!=NULL.
Does not close sockets */
static void remove_connect(struct dropbear_progress_connection *c, m_list_elem *iter) {
	if (c->res) {
		freeaddrinfo(c->res);
	}
	m_free(c->remotehost);
	m_free(c->remoteport);
	m_free(c->errstring);
	m_free(c->bind_address);
	m_free(c->bind_port);
	m_free(c);

	if (iter) {
		list_remove(iter);
	}
}

static void cancel_callback(int result, int sock, void* UNUSED(data), const char* UNUSED(errstring)) {
	if (result == DROPBEAR_SUCCESS)
	{
		m_close(sock);
	}
}

void cancel_connect(struct dropbear_progress_connection *c) {
	c->cb = cancel_callback;
	c->cb_data = NULL;
}

static void connect_try_next(struct dropbear_progress_connection *c) {
	struct addrinfo *r;
	int err;
	int res = 0;
	int fastopen = 0;
#if DROPBEAR_CLIENT_TCP_FAST_OPEN
	struct msghdr message;
#endif

	for (r = c->res_iter; r; r = r->ai_next)
	{
		dropbear_assert(c->sock == -1);

		c->sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (c->sock < 0) {
			continue;
		}

		if (c->bind_address || c->bind_port) {
			/* bind to a source port/address */
			struct addrinfo hints;
			struct addrinfo *bindaddr = NULL;
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = r->ai_family;
			hints.ai_flags = AI_PASSIVE;

			err = getaddrinfo(c->bind_address, c->bind_port, &hints, &bindaddr);
			if (err) {
				m_free(c->errstring);
				c->errstring = m_asprintf("Error resolving bind address '%s' (port %s). %s",
						c->bind_address, c->bind_port, gai_strerror(err));
				TRACE(("Error resolving bind: %s", gai_strerror(err)))
				close(c->sock);
				c->sock = -1;
				continue;
			}
			res = bind(c->sock, bindaddr->ai_addr, bindaddr->ai_addrlen);
			freeaddrinfo(bindaddr);
			bindaddr = NULL;
			if (res < 0) {
				/* failure */
				int keep_errno = errno;
				m_free(c->errstring);
				c->errstring = m_asprintf("Error binding local address '%s' (port %s): %s",
						c->bind_address, c->bind_port,
						strerror(keep_errno));
				close(c->sock);
				c->sock = -1;
				continue;
			}
		}

		ses.maxfd = MAX(ses.maxfd, c->sock);
		set_sock_nodelay(c->sock);
		set_sock_priority(c->sock, c->prio);
		setnonblocking(c->sock);

#if DROPBEAR_CLIENT_TCP_FAST_OPEN
		fastopen = (c->writequeue != NULL);

		if (fastopen) {
			memset(&message, 0x0, sizeof(message));
			message.msg_name = r->ai_addr;
			message.msg_namelen = r->ai_addrlen;
			/* 6 is arbitrary, enough to hold initial packets */
			unsigned int iovlen = 6; /* Linux msg_iovlen is a size_t */
			struct iovec iov[6];
			packet_queue_to_iovec(c->writequeue, iov, &iovlen);
			message.msg_iov = iov;
			message.msg_iovlen = iovlen;
			res = sendmsg(c->sock, &message, MSG_FASTOPEN);
			/* Returns EINPROGRESS if FASTOPEN wasn't available */
			if (res < 0) {
				if (errno != EINPROGRESS) {
					m_free(c->errstring);
					c->errstring = m_strdup(strerror(errno));
					/* Not entirely sure which kind of errors are normal - 2.6.32 seems to 
					return EPIPE for any (nonblocking?) sendmsg(). just fall back */
					TRACE(("sendmsg tcp_fastopen failed, falling back:"));
					/* No kernel MSG_FASTOPEN support. Fall back below */
					fastopen = 0;
					/* Set to NULL to avoid trying again */
					c->writequeue = NULL;
				}
			} else {
				packet_queue_consume(c->writequeue, res);
			}
		}
#endif

		/* Normal connect(), used as fallback for TCP fastopen too */
		if (!fastopen) {
			res = connect(c->sock, r->ai_addr, r->ai_addrlen);
		}

		if (res < 0 && errno != EINPROGRESS) {
			/* failure */
			m_free(c->errstring);
			c->errstring = m_strdup(strerror(errno));
			close(c->sock);
			c->sock = -1;
			continue;
		} else {
			/* new connection was successful, wait for it to complete */
			break;
		}
	}

	if (r) {
		c->res_iter = r->ai_next;
	} else {
		c->res_iter = NULL;
	}
}

/* Connect via TCP to a host. */
struct dropbear_progress_connection *connect_remote(const char* remotehost, const char* remoteport,
	connect_callback cb, void* cb_data,
	const char* bind_address, const char* bind_port, enum dropbear_prio prio)
{
	struct dropbear_progress_connection *c = NULL;
	int err;
	struct addrinfo hints;

	c = m_malloc(sizeof(*c));
	c->remotehost = m_strdup(remotehost);
	c->remoteport = m_strdup(remoteport);
	c->sock = -1;
	c->cb = cb;
	c->cb_data = cb_data;
	c->prio = prio;

	list_append(&ses.conn_pending, c);

#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		c->errstring = m_strdup("fuzzing connect_remote always fails");
		return c;
	}
#endif

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;

	err = getaddrinfo(remotehost, remoteport, &hints, &c->res);
	if (err) {
		c->errstring = m_asprintf("Error resolving '%s' port '%s'. %s", 
				remotehost, remoteport, gai_strerror(err));
		TRACE(("Error resolving: %s", gai_strerror(err)))
	} else {
		c->res_iter = c->res;
	}
	
	if (bind_address) {
		c->bind_address = m_strdup(bind_address);
	}
	if (bind_port) {
		c->bind_port = m_strdup(bind_port);
	}

	return c;
}

void remove_connect_pending() {
	while (ses.conn_pending.first) {
		struct dropbear_progress_connection *c = ses.conn_pending.first->item;
		remove_connect(c, ses.conn_pending.first);
	}
}


void set_connect_fds(fd_set *writefd) {
	m_list_elem *iter;
	iter = ses.conn_pending.first;
	while (iter) {
		m_list_elem *next_iter = iter->next;
		struct dropbear_progress_connection *c = iter->item;
		/* Set one going */
		while (c->res_iter && c->sock < 0) {
			connect_try_next(c);
		}
		if (c->sock >= 0) {
			FD_SET(c->sock, writefd);
		} else {
			/* Final failure */
			if (!c->errstring) {
				c->errstring = m_strdup("unexpected failure");
			}
			c->cb(DROPBEAR_FAILURE, -1, c->cb_data, c->errstring);
			remove_connect(c, iter);
		}
		iter = next_iter;
	}
}

void handle_connect_fds(const fd_set *writefd) {
	m_list_elem *iter;
	for (iter = ses.conn_pending.first; iter; iter = iter->next) {
		int val;
		socklen_t vallen = sizeof(val);
		struct dropbear_progress_connection *c = iter->item;

		if (c->sock < 0 || !FD_ISSET(c->sock, writefd)) {
			continue;
		}

		TRACE(("handling %s port %s socket %d", c->remotehost, c->remoteport, c->sock));

		if (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &val, &vallen) != 0) {
			TRACE(("handle_connect_fds getsockopt(%d) SO_ERROR failed:", c->sock))
			/* This isn't expected to happen - Unix has surprises though, continue gracefully. */
			m_close(c->sock);
			c->sock = -1;
		} else if (val != 0) {
			/* Connect failed */
			TRACE(("connect to %s port %s failed.", c->remotehost, c->remoteport))
			m_close(c->sock);
			c->sock = -1;

			m_free(c->errstring);
			c->errstring = m_strdup(strerror(val));
		} else {
			/* New connection has been established */
			c->cb(DROPBEAR_SUCCESS, c->sock, c->cb_data, NULL);
			remove_connect(c, iter);
			TRACE(("leave handle_connect_fds - success"))
			/* Must return here - remove_connect() invalidates iter */
			return; 
		}
	}
}

void connect_set_writequeue(struct dropbear_progress_connection *c, struct Queue *writequeue) {
	c->writequeue = writequeue;
}

void packet_queue_to_iovec(const struct Queue *queue, struct iovec *iov, unsigned int *iov_count) {
	struct Link *l;
	unsigned int i;
	int len;
	buffer *writebuf;

#ifndef IOV_MAX
	#if defined(__CYGWIN__) && !defined(UIO_MAXIOV)
		#define IOV_MAX 1024
	#elif defined(__sgi)
		#define IOV_MAX 512 
	#else 
		#define IOV_MAX UIO_MAXIOV
	#endif
#endif

	*iov_count = MIN(MIN(queue->count, IOV_MAX), *iov_count);

	for (l = queue->head, i = 0; i < *iov_count; l = l->link, i++)
	{
		writebuf = (buffer*)l->item;
		len = writebuf->len - writebuf->pos;
		dropbear_assert(len > 0);
		TRACE2(("write_packet writev #%d len %d/%d", i,
				len, writebuf->len))
		iov[i].iov_base = buf_getptr(writebuf, len);
		iov[i].iov_len = len;
	}
}

void packet_queue_consume(struct Queue *queue, ssize_t written) {
	buffer *writebuf;
	int len;
	while (written > 0) {
		writebuf = (buffer*)examine(queue);
		len = writebuf->len - writebuf->pos;
		if (len > written) {
			/* partial buffer write */
			buf_incrpos(writebuf, written);
			written = 0;
		} else {
			written -= len;
			dequeue(queue);
			buf_free(writebuf);
		}
	}
}

void set_sock_nodelay(int sock) {
	int val;

	/* disable nagle */
	val = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void*)&val, sizeof(val));
}

#if DROPBEAR_SERVER_TCP_FAST_OPEN
void set_listen_fast_open(int sock) {
	int qlen = MAX(MAX_UNAUTH_PER_IP, 5);
	if (setsockopt(sock, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0) {
		TRACE(("set_listen_fast_open failed for socket %d:", sock))
	}
}

#endif

void set_sock_priority(int sock, enum dropbear_prio prio) {

	int rc;
	int val;

#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		TRACE(("fuzzing skips set_sock_prio"))
		return;
	}
#endif
	/* Don't log ENOTSOCK errors so that this can harmlessly be called
	 * on a client '-J' proxy pipe */

	if (opts.disable_ip_tos == 0) {
#ifdef IP_TOS
	/* Set the DSCP field for outbound IP packet priority.
	rfc4594 has some guidance to meanings.

	We set AF21 as "Low-Latency" class for interactive (tty session,
	also handshake/setup packets). Other traffic is left at the default.

	OpenSSH at present uses AF21/CS1, rationale
	https://cvsweb.openbsd.org/src/usr.bin/ssh/readconf.c#rev1.284

	Old Dropbear/OpenSSH and Debian/Ubuntu OpenSSH (at Jan 2022) use
	IPTOS_LOWDELAY/IPTOS_THROUGHPUT

	DSCP constants are from Linux headers, applicable to other platforms
	such as macos.
	*/
	if (prio == DROPBEAR_PRIO_LOWDELAY) {
		val = 0x48; /* IPTOS_DSCP_AF21 */
	} else {
		val = 0; /* default */
	}
#if defined(IPPROTO_IPV6) && defined(IPV6_TCLASS)
	rc = setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (void*)&val, sizeof(val));
	if (rc < 0 && errno != ENOTSOCK) {
		TRACE(("Couldn't set IPV6_TCLASS:"));
	}
#endif
	rc = setsockopt(sock, IPPROTO_IP, IP_TOS, (void*)&val, sizeof(val));
	if (rc < 0 && errno != ENOTSOCK) {
		TRACE(("Couldn't set IP_TOS:"));
	}
#endif /* IP_TOS */
	}

#ifdef HAVE_LINUX_PKT_SCHED_H
	/* Set scheduling priority within the local Linux network stack */
	if (prio == DROPBEAR_PRIO_LOWDELAY) {
		val = TC_PRIO_INTERACTIVE;
	} else {
		val = 0;
	}
	/* linux specific, sets QoS class. see tc-prio(8) */
	rc = setsockopt(sock, SOL_SOCKET, SO_PRIORITY, (void*) &val, sizeof(val));
	if (rc < 0 && errno != ENOTSOCK) {
		TRACE(("Couldn't set SO_PRIORITY:"))
    }
#endif

}

/* Listen on address:port. 
 * Special cases are address of "" listening on everything,
 * and address of NULL listening on localhost only.
 * Returns the number of sockets bound on success, or -1 on failure. On
 * failure, if errstring wasn't NULL, it'll be a newly malloced error
 * string.*/
int dropbear_listen(const char* address, const char* portstring,
		int *socks, unsigned int sockcount, char **errstring,
		int *maxfd, unsigned int *portp) {

	struct addrinfo hints, *res = NULL, *res0 = NULL;
	int err;
	unsigned int nsock;
	int val;
	int sock;
	int port = 0;
	
	TRACE(("enter dropbear_listen"))

#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		return fuzz_dropbear_listen(address, portstring, socks, sockcount, errstring, maxfd);
	}
#endif
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* TODO: let them flag v4 only etc */
	hints.ai_socktype = SOCK_STREAM;

	/* for calling getaddrinfo:
	 address == NULL and !AI_PASSIVE: local loopback
	 address == NULL and AI_PASSIVE: all interfaces
	 address != NULL: whatever the address says */
	if (!address) {
		TRACE(("dropbear_listen: local loopback"))
	} else {
		if (address[0] == '\0') {
			TRACE(("dropbear_listen: all interfaces"))
			address = NULL;
		}
		hints.ai_flags = AI_PASSIVE;
	}
	err = getaddrinfo(address, portstring, &hints, &res0);

	if (err) {
		if (errstring != NULL && *errstring == NULL) {
			*errstring = m_asprintf("Error resolving: %s", gai_strerror(err));
		}
		if (res0) {
			freeaddrinfo(res0);
			res0 = NULL;
		}
		TRACE(("leave dropbear_listen: failed resolving"))
		return -1;
	}

	nsock = 0;
	for (res = res0; res != NULL && nsock < sockcount;
			res = res->ai_next) {
		/* Get a socket */
		socks[nsock] = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		sock = socks[nsock]; /* For clarity */
		if (sock < 0) {
			err = errno;
			TRACE(("socket() failed"))
			continue;
		}

		/* Various useful socket options */
		val = 1;
		/* set to reuse, quick timeout */
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &val, sizeof(val));

#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		if (res->ai_family == AF_INET6) {
			int on = 1;
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, 
						&on, sizeof(on)) == -1) {
				dropbear_log(LOG_WARNING, "Couldn't set IPV6_V6ONLY");
			}
		}
#endif
		set_sock_nodelay(sock);

		if (port > 0) {
			if (res->ai_family == AF_INET) {
				((struct sockaddr_in *)res->ai_addr)->sin_port
					= port;
			} else if (res->ai_family == AF_INET6) {
				((struct sockaddr_in6 *)res->ai_addr)->sin6_port
					= port;
			}
		}
		if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) {
			err = errno;
			close(sock);
			TRACE(("bind(%d) failed", ntohs(port)))
			continue;
		}

		if (port == 0) {
			getsockname(sock, res->ai_addr, &res->ai_addrlen);
			if (res->ai_family == AF_INET) {
				port = ((struct sockaddr_in*)res->ai_addr)->
					sin_port;
			} else if (res->ai_family == AF_INET6) {
				port = ((struct sockaddr_in6*)res->ai_addr)->
					sin6_port;
			}
		}

		if (listen(sock, DROPBEAR_LISTEN_BACKLOG) < 0) {
			err = errno;
			close(sock);
			TRACE(("listen() failed"))
			continue;
		}

		*maxfd = MAX(*maxfd, sock);
		nsock++;
	}

	if (res0) {
		freeaddrinfo(res0);
		res0 = NULL;
	}

	if (nsock == 0) {
		if (errstring != NULL && *errstring == NULL) {
			*errstring = m_asprintf("Error listening: %s", strerror(err));
		}
		TRACE(("leave dropbear_listen: failure, %s", strerror(err)))
		return -1;
	}

	if (port > 0 && portp) {
		*portp = ntohs(port);
	}

	TRACE(("leave dropbear_listen: success, %d socks bound", nsock))
	return nsock;
}

void get_socket_address(int fd, char **local_host, int *local_port,
		char **remote_host, int *remote_port, int opts) {
	union any_address addr;
	socklen_t addrlen = sizeof addr;

#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		fuzz_get_socket_address(fd, local_host, local_port, remote_host, remote_port, opts);
		return;
	}
#endif
	
	if (local_host || local_port) {
		if (getsockname(fd, &addr.sa, &addrlen) < 0) {
			dropbear_exit("Failed local socket address:");
		}
		getaddrstring(&addr.sa, addrlen, local_host, local_port, opts);
	}
	if (remote_host || remote_port) {
		if (getpeername(fd, &addr.sa, &addrlen) < 0) {
			dropbear_exit("Failed remote socket address:");
		}
		getaddrstring(&addr.sa, addrlen, remote_host, remote_port, opts);
	}
}

/* Return a string representation of the socket address passed. The return
 * value is allocated with malloc() */
void getaddrstring(struct sockaddr *addr, socklen_t addrlen,
		char **hostp, int *portp, int opts) {

	char host[NI_MAXHOST+1];
	unsigned int len;
	int ret, flags, port;
	
	if (addr->sa_family == AF_UNIX) {
		unsigned char *s = ((struct sockaddr_un*)addr)->sun_path;
		int len = addrlen - offsetof(struct sockaddr_un, sun_path);
		if (len > 0 && (s[0] || ABSTRACT_UNIX_SOCKETS)) {
			int i, j;
			char *d = *hostp = m_asprintf("unix:%*s", len * 4, "");
			for (i = 0, j = 5; i < len; i++) {
				switch(s[i]){
				case '\0':
					d[j++] = '@'; continue;
				case '\\':
				case '@':
				case '<':
					d[j++] = '\\'; d[j++] = s[i]; continue;
				}
				/* assume ascii */
				if (s[i] < ' ' || s[i] > '~') {
					snprintf(d + j, 5, "\\%03o", s[i]);
					j += 4;
				} else 
					d[j++] = s[i];
			}
			d[j] = '\0';
		} else
			*hostp = m_strdup("unix<anonymous>");
		if(portp) *portp = 0;
		return;
	}

#if DO_HOST_LOOKUP
	flags = opts & WITH_LOOKUP ? 0 : NI_NUMERICHOST;
#else
	flags = 0;
#endif
	if (addr->sa_family == AF_INET) {
		len = sizeof(struct sockaddr_in);
		port = ntohs(((struct sockaddr_in*)addr)->sin_port);
	}
#ifdef AF_INET6
	else if (addr->sa_family == AF_INET6) {
		len = sizeof(struct sockaddr_in6);
		port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	}
#endif
	else {
		*hostp = m_asprintf("<unknown socket type %d>", addr->sa_family);
		if(portp) *portp = 0;
		return;
	}
	ret = getnameinfo(addr, len, host, sizeof host - 1, 
			NULL, 0, flags);

	if (ret && flags != NI_NUMERICHOST) {
		/* On some systems (Darwin does it) we get EINTR from getnameinfo
		 * somehow. Eew. So we'll just return the IP, since that doesn't seem
		 * to exhibit that behaviour. */
		ret = getnameinfo(addr, len, host, sizeof host - 1, 
			NULL, 0, NI_NUMERICHOST);
	}
	if (ret) {
		/* if we can't do a numeric lookup, something's gone terribly wrong */
		dropbear_exit("Failed lookup: %s", gai_strerror(ret));
	}
	if (opts & FULL_ADDRESS) {
		*hostp = m_asprintf(strchr(host, ':') ? "%s:%d" : "[%s]:%d",
			host, port);
	} else if (hostp) {
		*hostp = m_strdup(host);
	}
	if(portp) *portp = port;
}

