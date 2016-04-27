#include <config.h>
#include <cyassl/ssl.h> /* name change portability layer */
#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/openssl/ssl.h>
#include <cyassl/test.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "selectserver.h"

// buffers
//static const int buffcapacity = 1500; // TODO: there is probably a more efficient upper limit than 1500 bytes
#define buffcapacity 5000
int cipher_receive_sz = 0;
int cipher_send_sz = 0;
int clear_receive_sz = 0;
int clear_send_sz = 0;

char cipher_receive[buffcapacity];
char cipher_send[buffcapacity];
char clear_receive[buffcapacity];
char clear_send[buffcapacity];

int _serverSocketFd6 = 0;
int _acceptedSocketFd6 = 0;
fd_set rfds;
fd_set wfds;
int nfds = 0;

SSL_METHOD* method = 0;
SSL_CTX*    ctx    = 0;
SSL*        ssl_session    = 0;
int         ssl_accepted = 0;
int         ssl_shutdown = 0;
int         ssl_datawritten = 0;
char   msg[] = "I hear you fa shizzle!";
char   input[80];

int bindListeningSocket(void) {
  // Open socket, set options, bind to address
  _serverSocketFd6 = socket(AF_INET6, SOCK_STREAM, 0);
  if (_serverSocketFd6 < 0)
    return 1;

  int sockopt = 1;
  if (setsockopt(_serverSocketFd6, SOL_SOCKET, SO_REUSEADDR, (void *)&sockopt, sizeof(sockopt)) < 0)
    return 2;

  // bind to port
  struct sockaddr_in6 sin6;

  sin6.sin6_family = AF_INET6;
  sin6.sin6_flowinfo = 0;
  sin6.sin6_port = htons(11111);
  //sin6.sin6_addr = in6addr_any;
  // Old code (when IP was used)
  //memcpy(sin6.sin6_addr.__in6_u.__u6_addr8,_myIP6.in6_addr().s6_addr,16);
  inet_pton(AF_INET6, "::1", &sin6.sin6_addr);

  if (bind(_serverSocketFd6, (struct sockaddr *)&sin6, sizeof(sin6)) < 0)
  {
    return 3;
  }

  // start listening (queue up to 10 connections)
  if (listen(_serverSocketFd6, 10) < 0)
    return 4;

  // nonblocking I/O and close-on-exec for the socket
  fcntl(_serverSocketFd6, F_SETFL, O_NONBLOCK);
  fcntl(_serverSocketFd6, F_SETFD, FD_CLOEXEC);

  FD_SET(_serverSocketFd6, &rfds);
  nfds = _serverSocketFd6;

  return 0;
}

void NonBlockingSSL_Accept(SSL* ssl)
{
    int ret = SSL_accept(ssl);

    int error = SSL_get_error(ssl, 0);
    if (ret != SSL_SUCCESS && (error == SSL_ERROR_WANT_READ ||
                               error == SSL_ERROR_WANT_WRITE)) {
        //int currTimeout = 1;

        if (error == SSL_ERROR_WANT_READ)
            printf("... server would read block\n");
        else
            printf("... server would write block\n");
    } else if (ret == SSL_SUCCESS) {
      printf("Accepted SSL session\n");
      ssl_accepted = 1;
    } else {
      err_sys("SSL_accept failed");
    }
}

/*
			CyaSSL callbacks
*/
/*
* 	buf points to the buffer where incoming cipher text should be copied for CyaSSL to decrypt and sz is the size of the buffer
* 	buf = clear_receive (passed as argument in CyaSSL_read)
*/
int recvFrom(CYASSL *ssl, char *buf, int sz, void *ctx2) {
  (void)(ctx2);
  (void)(ssl);
  (void)(sz);
  printf("recvFrom: CyaSSL is requesting %d bytes from application. Application has cipher_receive_sz = %d bytes buffered.\n", sz,cipher_receive_sz);
  //printf("recvFrom, receiving DTLS message of %d bytes via Click\n", cipher_receive_sz);

#ifdef DEBUG_L0
	// View msg content
  for (int i=0;i<sz;i++) {
    printf("recvFrom %02x\n", cipher_receive[i]);
  }
#endif

  // if cipher_receive buffer is empty
  if (!cipher_receive_sz) {
    printf("recvFrom: WARNING cipher_receive_sz buffer is empty!\n");
  	return -2;
  }
  // else copy sz bytse from received cipher text in buffer for CyaSSL to decrypt
  if (sz > cipher_receive_sz) { // cyaSSL is asking to copy more bytes than we have available
    printf("recvFrom: WARNING requested sz too large, trunking to cipher_receive_sz\n");
    sz = cipher_receive_sz;
  }
  memcpy(buf, cipher_receive, sz);

  // Store the number of bytes we copied, so we can return it later
  int ret = sz;

  // Update buffer
  if (cipher_receive_sz > sz) { // move buffer
    int i;
    for (i = 0; i < cipher_receive_sz - sz; i++) {
      cipher_receive[i] = cipher_receive[sz + i];
    }
  }
  cipher_receive_sz -= sz;

  // now that all the data has been copied, reset the number of bytes to copy
  //cipher_receive_sz = 0;

  // return number of copied bytes
  return ret;
}

/*
* 	buf points to the buffer where CyaSSL has written cipher text to be sent and sz is the size of encrypted data
*/
int sendTo(CYASSL *ssl, char *buf, int sz, void *ctx2) {
  (void)(ctx2);
  (void)(ssl);
  printf("sendTo: copying %d bytes to cipher_send output buffer, cipher_send_sz = %d\n", sz, cipher_send_sz);

#ifdef DEBUG_L0
  printf("sendTo printing DTLS message:\n");
	// View msg content
  for (int i=0;i<sz;i++) {
  	printf("sendTo %02x", buf[i]);
  }
#endif

  // if data too big for buffer
  if (sz + cipher_send_sz > buffcapacity) {
    printf("sendTo ERROR %d bytes too big for buffercapacity!\n", sz + cipher_send_sz);
  	return -2;
  }
  else {
  	// copy buffer
		memcpy(cipher_send + cipher_send_sz, buf, sz);
		// set buffer size
		cipher_send_sz += sz;
		// notify DTLSModule that msg can be sent
    //add_select(_acceptedSocketFd6, SELECT_WRITE);
    FD_SET(_acceptedSocketFd6, &wfds);
		return sz;
	}
}

void selected(int fd)
{
  printf("selected called with fd = %d\n", fd);
  // Incoming HTTP connection on main listening socket of our server
  if (fd == _serverSocketFd6)
    {
      struct sockaddr_in6 dest_sin6;
      char buf[2048];

      socklen_t socklen;

      socklen = sizeof(dest_sin6);
      int newSockFd6 = accept(_serverSocketFd6, (struct sockaddr *)&dest_sin6, &socklen);

      // Disable SIGPIPE signals for this socket, instead we will handle broken pipes by processing the return values of socket read/send calls
      signal(SIGPIPE, SIG_IGN); // TODO: this seems to have no effect?

      inet_ntop(dest_sin6.sin6_family, dest_sin6.sin6_addr.__in6_u.__u6_addr8, buf, 2048);

      fcntl(newSockFd6, F_SETFL, O_NONBLOCK);
      fcntl(newSockFd6, F_SETFD, FD_CLOEXEC);
      //add_select(newSockFd6, SELECT_READ);
      //if (!FD_ISSET(newSockFd6, &rfds))
      FD_SET(newSockFd6, &rfds);

      //_incomingHttpRequest.insert(newSockFd6, HttpParser());
      //_outgoingHttpResponse.insert(newSockFd6, String());
      //_socketState.insert(newSockFd6, WAITING_FOR_HTTP_REQUEST);

      fd = newSockFd6;
      _acceptedSocketFd6 = newSockFd6;

      ssl_session = SSL_new(ctx);
      if (ssl_session == NULL)
        err_sys("unable to get SSL");

      SSL_set_fd(ssl_session, _acceptedSocketFd6);
      CyaSSL_set_using_nonblock(ssl_session, 1);

      return;
    }

  // Event on an established TCP connection
  // Try to read
  char buf[16384];
  int r = read(fd, buf, 16384);
  printf("read() returned %d\n", r);
  if (r > 0) { // store cipher text in cipher_receive buffer
    if (r > buffcapacity) {
      printf("ERROR read more bytes than buffcapacity, TRUNKING\n");
      r = buffcapacity;
    }
    if (cipher_receive_sz != 0) {
      err_sys("ERROR trying to copy to cipher_receive buffer while it is not empty");
    } else {
      memcpy(cipher_receive, buf, r);
      cipher_receive_sz = r;
    }
  } else {
    SSL_shutdown(ssl_session);
    //int ret = SSL_shutdown(ssl_session);
    //if (wc_shutdown && ret == SSL_SHUTDOWN_NOT_DONE)
            //SSL_shutdown(ssl_session);    /* bidirectional shutdown */
    SSL_free(ssl_session);
    ssl_shutdown = 1;
    FD_CLR(_acceptedSocketFd6, &rfds);
    close(_acceptedSocketFd6);
    _acceptedSocketFd6 = 0;
    return;
  }

  // Try to process read data
  if (!ssl_accepted) {
    printf("calling NonBlockingSSL_Accept with fd = %d\n", fd);
    NonBlockingSSL_Accept(ssl_session);
  } else { // SSL accepted, so handshake finished ...
    //showPeer(ssl_session);
    int    idx;
    idx = SSL_read(ssl_session, input, sizeof(input)-1);
    printf("SSL_read returned %d\n", idx);
    if (idx > 0) {
      input[idx] = 0;
      printf("Client message: %s\n", input);
    }
    else if (idx < 0) {
      int readErr = SSL_get_error(ssl_session, 0);
      if (readErr != SSL_ERROR_WANT_READ)
        err_sys("SSL_read failed");
    }

    if (SSL_write(ssl_session, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");
    ssl_datawritten = 1;
  }

  // try to write
  if (cipher_send_sz > 0) {
      int32_t numberOfBytesWritten = send(_acceptedSocketFd6, cipher_send, cipher_send_sz, MSG_NOSIGNAL);
      printf("selected numberOfBytesWritten = %d\n", numberOfBytesWritten);

      if (numberOfBytesWritten == cipher_send_sz) {
        cipher_send_sz = 0;
        FD_CLR(_acceptedSocketFd6, &wfds);
        if (ssl_datawritten) { // data written, so shutdown
          FD_CLR(_acceptedSocketFd6, &rfds);
          SSL_shutdown(ssl_session);
          SSL_free(ssl_session);
          ssl_shutdown = 1;
          close(_acceptedSocketFd6);
          _acceptedSocketFd6 = 0;
        }
      } else if (numberOfBytesWritten < 0) {
        if (errno == ENOBUFS || errno == EAGAIN)
        {
          printf("VirtualCOAPManagementModule::selected -> ERROR ENOBUFS or EAGAIN");
          // IMPROVEMENT -> add backoff (See SuperDev)
        }
        else
        {
          printf("VirtualCOAPManagementModule::selected -> ERROR %u, throwing away data\n", errno);
          // Failed -> throw away data by setting cipher_send_sz again
          cipher_send_sz = 0;
          // error, remove select
          //remove_select(_acceptedSocketFd6, SELECT_WRITE);
          FD_CLR(_acceptedSocketFd6, &wfds);
        }
      } else if (numberOfBytesWritten < cipher_send_sz) {
        printf("VirtualCOAPManagementModule::selected -> only %d of %d writen, updating send buffer", numberOfBytesWritten, cipher_send_sz);

        cipher_send_sz -= numberOfBytesWritten;
        memmove(cipher_send, cipher_send+numberOfBytesWritten, cipher_send_sz);
      }
  }
}

int main()
{
  CyaSSL_Init();
  //CyaSSL_Debugging_ON();

  // configure CyaSSL:
  method = TLSv1_2_server_method();

  if (method == NULL)
      err_sys("unable to get method");

  ctx = SSL_CTX_new(method);
  if (ctx == NULL)
      err_sys("unable to get ctx");

  const char* ourCert    = svrCert;
  const char* ourKey     = svrKey;

  if (SSL_CTX_use_certificate_file(ctx, ourCert, SSL_FILETYPE_PEM)
      != SSL_SUCCESS) {
    err_sys("can't load server cert file, check file and run from"
        " wolfSSL home dir");
}

  if (SSL_CTX_use_PrivateKey_file(ctx, ourKey, SSL_FILETYPE_PEM)
                                    != SSL_SUCCESS) {
      err_sys("can't load server private key file, check file and run "
          "from wolfSSL home dir");
  }

	// set send/receive callbacks
	// these replace low-level functions in CyaSSL (that were using sockets, set in io.c)
	CyaSSL_SetIORecv(ctx, &recvFrom);
	CyaSSL_SetIOSend(ctx, &sendTo);

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);

  int ret = bindListeningSocket();
  printf("bindListeningSocket() returned %d\n", ret);

  //struct timeval tv;
  while (!ssl_shutdown) {
    if (ssl_accepted) {
      nfds = _acceptedSocketFd6;
    }

    printf("Calling select()\n");
    select(_serverSocketFd6 > _acceptedSocketFd6 ? _serverSocketFd6 + 1 : _acceptedSocketFd6 + 1, &rfds, &wfds, NULL, NULL);
    printf("select() returned\n");
    int selectedServerSocket = FD_ISSET(_serverSocketFd6, &rfds);
    int selectedAcceptedSocket = FD_ISSET(_acceptedSocketFd6, &rfds) || FD_ISSET(_acceptedSocketFd6, &rfds);

    if (selectedServerSocket)
      selected(_serverSocketFd6);
    if (selectedAcceptedSocket)
      selected(_acceptedSocketFd6);
  }

  printf("Exited while loop\n");

  SSL_CTX_free(ctx);
  // close sockets
  return 0;
}
