#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

// DEFINITIONS
#define SUCCESS 0x0
#define ERROR -1
#define VERSION_SOCKS5  0x5
#define ATYP_IPV4       0x1
#define CMD_CONNECT     0x1

#define IPV4_REQUEST_LEN 10
#define BUFFER_SIZE 65536

//

struct __attribute__((__packed__)) ipv4_request{
    char version;
    char cmd;
    char rsv;
    char atyp;
    struct in_addr dst_addr;
    uint16_t dst_port;
};

struct __attribute__((__packed__)) ipv4_response{
    char version;
    char rep;
    char rsv;
    char atyp;
    struct in_addr bnd_addr;
    uint16_t bnd_port;
};

struct thread_args{
    int sockfd;
    struct sockaddr_in saddr_in;
};

pthread_mutex_t lock;

int sock_read(int sock, void* dst_buffer, int count){
    int len;
    int remainder = count;

    while(remainder > 0){
        if((len = read(sock, dst_buffer, remainder)) == ERROR){
            if(errno == EINTR || errno == EAGAIN)
                continue;
        }else{
            if(len == 0)
                return 0;
            remainder -= len;
            dst_buffer += len;
        }
    }

    return len;
}

int sock_write(int sock, void* src_buffer, int count){
    int len;
    int remainder = count;

    while(remainder > 0){
        if((len = write(sock, src_buffer, remainder)) == ERROR){
            if(errno == EINTR || errno == EAGAIN)
                continue;
        }else{
            if(len == count)
                return 0;
            remainder -= len;
            src_buffer += len;
        }
    }
    return len;
}

void print_banner(){
    printf("--===SOCKS5=PROXY===--\n By: Axua\n");
}

void print_usage(char* name){
    printf("USAGE: %s <LPORT>\n", name);
    exit(0);
}

int socks5_init(int sock){
    char buf[2];
    char* methods;
    int len;
    int nmethods;
    char resp = 0xFF;

    sock_read(sock, (void*)buf, 2);

    if(buf[0] != VERSION_SOCKS5){
        return 1;
    }

    nmethods = buf[1];
    methods = (char*)malloc(nmethods);

    len = sock_read(sock, (void*)methods, nmethods);

    for(int i = 0; i < len; i++){
        if(methods[i] == 0x00) // no-auth
            resp = 0x00;
    }

    buf[0] = VERSION_SOCKS5;
    buf[1] = resp;

    sock_write(sock, (void*)buf, 2);

    free(methods);
    return (resp == 0x00) ? SUCCESS : ERROR;
}

int socks5_connect(int cli_sock, struct sockaddr_in cli_addr){
    int len;
    int target_sock;
    int state;
    char buffer[IPV4_REQUEST_LEN];
    struct sockaddr_in saddr;
    struct ipv4_response response;
    struct ipv4_request* request;
    
    bzero(&saddr, sizeof(struct sockaddr_in));

    len = sock_read(cli_sock, (void*)buffer, IPV4_REQUEST_LEN);
    if(len != IPV4_REQUEST_LEN)     return ERROR; // invalid length
    if(buffer[0] != VERSION_SOCKS5) return ERROR; // only socks5 is supported
    if(buffer[1] != ATYP_IPV4)      return ERROR; // only connect is supported
    if(buffer[3] != CMD_CONNECT)    return ERROR; // only ipv4 is supported
    
    request = (struct ipv4_request*)malloc(sizeof(struct ipv4_request));
    memcpy(request, buffer, sizeof(struct ipv4_request));
    
    target_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(target_sock < 0){
        pthread_mutex_lock(&lock);
        fprintf(stderr, "[!] Socket creation failed\n");
        pthread_mutex_unlock(&lock);
        exit(1);
    }

    saddr.sin_family = AF_INET;
    saddr.sin_addr = request->dst_addr;
    saddr.sin_port = request->dst_port;

    printf("[+] %s:%d -> ", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
    printf("%s:%d\n", inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

    state = connect(target_sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr));

    response.version = VERSION_SOCKS5;
    response.rep = (state == 0) ? 0x0 : 0x5;
    response.rsv = 0x0;
    response.atyp = 0x1;
    response.bnd_addr = request->dst_addr;
    response.bnd_port = request->dst_port;

    sock_write(cli_sock, (void*)&response, sizeof(struct ipv4_response));



    return target_sock;
}

void forward_traffic(int client, int remote){
    int in, out;
    int ret;
    int state;
    int maxfd = (client > remote) ? client : remote;
    fd_set readfs;
    char buffer[BUFFER_SIZE];

    for(;;){
        FD_ZERO(&readfs);
        FD_SET(remote, &readfs);
        FD_SET(client, &readfs);
    
        ret = select(maxfd+1, &readfs, NULL, NULL, NULL);
        
        if(ret == 0 && errno == EINTR)
            continue;
        
        if(FD_ISSET(client, &readfs)){
            in = recv(client, buffer, BUFFER_SIZE, 0);
            if(in <= 0)
                break;
            send(remote, buffer, in, 0);
        }

        if(FD_ISSET(remote, &readfs)){
            out = recv(remote, buffer, BUFFER_SIZE, 0);
            if(out <= 0)
                break;
            send(client, buffer, out, 0);
        }
        

    }
    close(client);
    close(remote);
}

void* connection_handler(void* t_args){
    struct thread_args args = *(struct thread_args*)t_args;
    int cli_sock = args.sockfd;
    int remote_sock;

    if(socks5_init(cli_sock) == ERROR){
        close(cli_sock);
        pthread_mutex_lock(&lock);
        fprintf(stderr, "[-] unsupported authentication methods given\n");
        pthread_mutex_unlock(&lock);
        pthread_exit(0);
    }
    
    if((remote_sock = socks5_connect(cli_sock, args.saddr_in)) == ERROR){
        close(cli_sock);
        pthread_mutex_lock(&lock);
        fprintf(stderr, "[-] Unsupported request\n");
        pthread_mutex_unlock(&lock);
        pthread_exit(0);
    }

    forward_traffic(cli_sock, remote_sock);
}

void socks5_proxy(int16_t lport){
    int srv_sock, cli_sock;
    struct sockaddr_in srv_addr, cli_addr;
    struct thread_args args;
    socklen_t cli_len;
    
    if((srv_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        fprintf(stderr,"[!] Socket creation failed\n");
        exit(1);
    }

    bzero(&srv_addr, sizeof(srv_addr));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = lport;

    if(bind(srv_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0){
        fprintf(stderr, "[!] Failed to bind\n");
        exit(1);
    }

    if(listen(srv_sock, 50) < 0){
        fprintf(stderr, "[+] Failed to listen\n");
        exit(1);
    }

    printf("[+] Listening on port %d\n", ntohs(lport));

    cli_len = sizeof(cli_addr);
    bzero(&cli_addr, cli_len);

    pthread_t thread;

    for(;;){
        if((cli_sock = accept(srv_sock, (struct sockaddr*)&cli_addr, &cli_len)) < 0){
            fprintf(stderr, "[!] Failed to accept\n");
            exit(1);
        }

        int optval = 1;
        setsockopt(cli_sock, SOL_TCP, TCP_NODELAY, &optval, sizeof(optval));
        args.sockfd = cli_sock;
        args.saddr_in = cli_addr;
        if(pthread_create(&thread, NULL, connection_handler, &args) == 0){
            pthread_detach(thread);
        }else{
            fprintf(stderr,"[!] pthread_create failed\n");
        }
    }    

}

int main(int argc, char**argv){
    
    int srvsock;
    int port;

    setbuf(stdout, NULL);
    print_banner();
    if(argc != 2) print_usage(argv[0]);
    port = atoi(argv[1]);
    if(port > 65535 || port < 1){
        fprintf(stderr, "[!]Invalid port given\n");
        exit(1);
    }

    pthread_mutex_init(&lock, NULL);
    socks5_proxy(htons(port));

    return 0;
}