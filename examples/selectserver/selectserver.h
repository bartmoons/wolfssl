
int bindListeningSocket(void);
void NonBlockingSSL_Accept(SSL* ssl);
int recvFrom(CYASSL *ssl, char *buf, int sz, void *ctx);
int sendTo(CYASSL *ssl, char *buf, int sz, void *ctx);
void selected(int fd);
int main();
