#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// select() system call
#include <sys/select.h>

// Netlink
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

// TUN interface
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

// Security
#include <openssl/sha.h>


#define PASSWORD_SIZE 32
#define USERNAME_SIZE 32
#define DATA_MAX_SIZE 512
#define RANDOM_SIZE   16

#define VNP_PORT    8888
#define MAX_CLIENTS 30
#define MSS         1460

// It sets all the buffer to zero
#define ZERO(ptr, size)\
    memset(ptr, 0, size)
// It copies a buffer into another
#define MOVE(dst, src, size, offset)\
    memmove(dst + offset, src, size)
#define NETLINK_MSG_TAIL(nl_msg_header)\
    ((struct rtattr *) (((void *) (nl_msg_header)) + NLMSG_ALIGN((nl_msg_header)->nlmsg_len)))
// It does return the size of the C-struct rattr with some payload
#define ATTRIBUTE_SIZE(attribute_value_len)\
    ((unsigned int) RTA_ALIGN(RTA_LENGTH(attribute_value_len)))
// Get an IP address from octects
#define IP_ADDRESS_FROM_OCTETS(fst, snd, thd, fth)\
    ((fst << 24) + (snd << 16) + (thd << 8) + (fth))

enum Command {
    USERNAME, CHALLENGE, RESPONSE, FAILURE, SUCCESS
};
struct Message {
    enum Command cmd;
    char data [DATA_MAX_SIZE + 1];
};
struct Connection {
    int cs;
    struct sockaddr_in cin;
};

static int 
init_fds (struct Connection *cconn, int max, fd_set * readfds) {

    int i;
    int cs;
    int new_max;

    new_max = max;
    for(i=0; i<MAX_CLIENTS; i++) {
        cs = cconn[i].cs;
        if(cs > 0)
            FD_SET(cs, readfds);
        if(cs > max) 
            new_max = cs;
    }
    return new_max;
}
static void
regst_cs (struct Connection *ccon, struct sockaddr_in cin, int cs) {

    int i;

    for (i=0; i<MAX_CLIENTS; i++) {
        if(ccon[i].cs == 0)  {
            ccon[i].cs  = cs; 
            ccon[i].cin = cin;
            break;
        }
    }
    return;
}

static void
dump_hex_message (const char * buf, int size) {

    for(int i=0; i<size; i++) {
        printf("0x%02x ", (unsigned char) buf[i]);
        if(i % 12 == 0 && i) {
            printf("\n");
        }
    }
    printf("\n");
    return;
}
static int
start_service (int port) {

    int s, n;
    struct sockaddr_in sin;

    ZERO (&sin, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons (port);

    sin.sin_addr.s_addr = htonl (INADDR_ANY);
    s = socket (AF_INET, SOCK_STREAM, 0);

    if (s < 0)
        goto sock_creation;
    n = 1;
    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof (n)) < 0) 
        goto sock_options;
    if (bind (s, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        goto sock_binding;
    if (listen (s, 5) < 0) 
        goto sock_listening;

    fprintf(stdout, "[+] Service is up and running\n");
    fprintf(stdout, "    Local Address: %s\n", inet_ntoa(sin.sin_addr));
    fprintf(stdout, "    Port:          %u\n\n", ntohs(sin.sin_port));
    return s;

sock_creation:
    fprintf(stderr, "[-] Socket creation has failed\n");
    return -1;
sock_binding:
    fprintf(stderr, "[-] Socket creation has failed\n");
    close (s);
    return -1;
sock_options:
    fprintf(stderr, "[-] Socket settings has failed\nn");
    close (s);
    return -1;
sock_listening:
    fprintf(stderr, "[-] Socket listening has failed\n");
    close (s);
    return -1;

}   
static int
client_authentication (int cs, struct Connection *cconn) {

    FILE  *file;
    int    n;
    int    found;

    struct sockaddr_in cin;
    struct Message msg;

    char buffer   [USERNAME_SIZE + PASSWORD_SIZE + RANDOM_SIZE];
    char username [PASSWORD_SIZE + 1];
    char password [USERNAME_SIZE + 1];

    ZERO(username, PASSWORD_SIZE + 1);
    ZERO(password, PASSWORD_SIZE + 1);
    
    char  random   [  ] = "ABCDABCDABCDABCD";
    char  digest   [SHA256_DIGEST_LENGTH];

    char  cip  [INET_ADDRSTRLEN];
    char  mask [INET_ADDRSTRLEN];

    // Receive username
    ZERO(&msg, sizeof(struct Message));
    if (read (cs, (void*) &msg, sizeof(msg.cmd) + DATA_MAX_SIZE + 1) == 0)
        goto disconneted;

    // Search username
    if((file = fopen("server/users.dat", "r")) == NULL)
        goto io_err;
    

    found = 0;
    while (fscanf(file, "%s %s\n", username, password) == 2) {
        if(strcmp(msg.data, username) == 0) {
            found = 1;
            break;
        }
    }
    fclose(file);
    if(!found) 
        goto failure;   
    
    // Looup for an IP
    if((file = fopen("server/ips.dat", "r")) == NULL)
        goto io_err;
        found = 0;
    found = 1;
    while (fscanf(file, "%s %s %d\n", cip, mask, &found) == 3) {
        if(found)
            break;
    }
    fclose(file);
    if(!found) 
        goto failure;

    ZERO    (buffer, USERNAME_SIZE + PASSWORD_SIZE + RANDOM_SIZE);
    MOVE    (buffer, username, strlen(username), 0x00);
    MOVE    (buffer, password, strlen(password), strlen(username));
    MOVE    (buffer, random,   strlen(random),   strlen(username) + strlen(password));
    SHA256  (buffer, strlen(username) + strlen(password) + strlen(random), digest);   // SHA256 ([username | password | random])

    // Send challenge
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = CHALLENGE;
    memcpy(msg.data, random, strlen(random) + 1);
    write (cs, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);

    // Receive response
    ZERO(&msg, sizeof(struct Message));
    if (read (cs, (void*) &msg, sizeof(msg.cmd) + DATA_MAX_SIZE + 1) == 0)
        goto disconneted;

    digest   [SHA256_DIGEST_LENGTH] = '\0';
    msg.data [SHA256_DIGEST_LENGTH] = '\0';

    if(strcmp(digest, msg.data) == 0)
        goto success;
    else
        goto failure;

io_err:
    fprintf(stdout, "[-] Couldn't open file\n");
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = FAILURE;
    write (cs, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);
    return 0;
failure:
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = FAILURE;
    write (cs, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);
    return 0;
success:
    // Register new client
    ZERO(&cin, sizeof(struct sockaddr_in));
    cin.sin_addr.s_addr = inet_addr(cip);
    regst_cs(cconn, cin, cs);
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = SUCCESS;
    sprintf(msg.data, "%s %s", cip, mask);
    write (cs, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);
    return 1;
disconneted:
    return -1;

}


static int
is_ipv4 (char * buf) {
    return ((buf[0] & 0xF0) >> 4) == 0x04;
}
static int 
from_ascii_to_int (char *addr) {

    unsigned int fst;
    unsigned int snd;
    unsigned int thd;
    unsigned int fth;

    sscanf(addr, "%u.%u.%u.%u", &fst, &snd, &thd, &fth);
    return IP_ADDRESS_FROM_OCTETS(fst, snd, thd, fth);
}
static int
belongs_to_net (unsigned int net, unsigned int netmask, unsigned int addr) {

    if((net & netmask) == (addr & netmask)) 
        return 1;
    return 0;
}

static void 
handle_cs (int *cs, struct sockaddr_in cin, char *net, char *netmask, int tun) {

    int n;
    unsigned int dst;
    char buf [MSS];

    if ((n = read(*cs , buf, MSS)) == 0) {
        fprintf(stdout, "   [+] End connection:");
        fprintf(stdout, " - Addr: %s", inet_ntoa(cin.sin_addr));
        fprintf(stdout, " - Port: %u\n", ntohs(cin.sin_port));
        close(cs);
        *cs = 0;
    } else {
        if(is_ipv4(buf)) { // If it is an IPv4 packet
            dst = ntohl(*(unsigned int*)(buf + 16));
            if(belongs_to_net(from_ascii_to_int(net), from_ascii_to_int(netmask), dst))
                printf("FORWARD THIS!\n");
                write (tun, (const void*) buf, n);
        }
    }
    return;
}
static void 
handle_tun (int tun, char *net, char *netmask, struct Connection *ccon) {

    int n, i;
    unsigned int src;
    unsigned int dst;
    char buf [MSS];

    if ((n = read(tun , buf, MSS)) == 0) {
        // TO DO
        printf("Nothing\n");
    } else {
        if(is_ipv4(buf)) { // If it is an IPv4 packet
            src = ntohl(*(unsigned int*)(buf + 12));
            dst = *(unsigned int*)(buf + 16);
            if(belongs_to_net(from_ascii_to_int(net), from_ascii_to_int(netmask), src)) {
                for(i=0; i<MAX_CLIENTS; i++) {
                    if(ccon[i].cin.sin_addr.s_addr == dst) {
                        printf("Sendind to %d\n", ccon[i].cs);
                        printf("Sending %d vs %d\n", write (ccon[i].cs, (const void*) buf, n), n);
                        break;
                    }
                }
            }
        }
    }
    return;
}

static int
tun_alloc(char *dev) {

    struct ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
       return -1;

    ZERO(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(*dev)
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
       close(fd);
       return -1;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}
static int 
add_att (void *req, void *attval, int attlen, int attype, int maxsz) {

    // Cast the request
    struct nlmsghdr * header = (struct nlmsghdr *) req;
    // Check if there is space enough
    if(header->nlmsg_len + ATTRIBUTE_SIZE(attlen) > maxsz) {
        printf(" *** Error, exceeding the maximum request length of %d ***\n", maxsz);
        return -1;
    }

    // Define the attribute
    struct rtattr   * attribute_ptr;

    attribute_ptr           = NETLINK_MSG_TAIL(header);
    attribute_ptr->rta_type = attype;
    attribute_ptr->rta_len  = RTA_LENGTH(attlen);

    memcpy(RTA_DATA(attribute_ptr), attval, attlen);
    header->nlmsg_len = NLMSG_ALIGN(header->nlmsg_len) + ATTRIBUTE_SIZE(attlen);

    return 0;
}
static int 
set_addr (char *dev, char *addr, int prefx) {

    // Address attribute buffer
    struct in_addr iaddr;

    // NETLINK request schema ....
    // struct nlmsghdr {
    //    __u32 nlmsg_len;    /* Length of message including header */
    //    __u16 nlmsg_type;   /* Type of message content */
    //    __u16 nlmsg_flags;  /* Additional flags */
    //    __u32 nlmsg_seq;    /* Sequence number */
    //    __u32 nlmsg_pid;    /* Sender port ID */
    //  };

    //  +

    //  struct ifaddrmsg {
    //     unsigned char ifa_family;    /* Address type */
    //     unsigned char ifa_prefixlen; /* Prefixlength of viface_address */
    //     unsigned char ifa_flags;     /* Address flags */
    //     unsigned char ifa_scope;     /* Address scope */
    //     unsigned int  ifa_index;     /* Interface index */
    //   };

    // +

    // struct rtattr {
    //    unsigned short rta_len;    /* Length of option */
    //    unsigned short rta_type;   /* Type of option */
    //    struct in_addr address;
    //  };

    // +

    // struct rtattr {
    //    unsigned short rta_len;    /* Length of option */
    //    unsigned short rta_type;   /* Type of option */
    //    struct in_addr address;
    //  };

    // ... NETLINK request schema in C-struct  ....
    struct {
        struct nlmsghdr   header;
        struct ifaddrmsg  payload;
        char   attributes [ATTRIBUTE_SIZE(sizeof(struct in_addr)) * 2];
    } nl_msg;

    // Init memory location to 0x00
    ZERO(&nl_msg,     sizeof(nl_msg));
    ZERO(&iaddr, sizeof(struct in_addr));

    // Define the NETLINK header
    nl_msg.header.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nl_msg.header.nlmsg_flags = NLM_F_REQUEST;
    nl_msg.header.nlmsg_type  = RTM_NEWADDR;
    // Define the NETLINK ROUTE header
    nl_msg.payload.ifa_family    = AF_INET;
    nl_msg.payload.ifa_index     = if_nametoindex(dev);
    nl_msg.payload.ifa_prefixlen = (unsigned char) prefx;
    // Make viface_address from presentation layout to network layout
    inet_pton(AF_INET, addr, &iaddr);
    // Add attributes
    add_att(
            &nl_msg,
            &iaddr,
            sizeof(struct in_addr),
            IFA_LOCAL,
            nl_msg.header.nlmsg_len + ATTRIBUTE_SIZE(sizeof(struct in_addr)) * 2);
    add_att(
            &nl_msg,
            &iaddr,
            sizeof(struct in_addr),
            IFA_ADDRESS,
            nl_msg.header.nlmsg_len + ATTRIBUTE_SIZE(sizeof(struct in_addr)) * 2);

    // Have a new socket
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(fd < 0) {
        return -1;
    }

    // Send the nl_msg
    ssize_t n = send(fd, &nl_msg, nl_msg.header.nlmsg_len, 0x00);
    if(n < sizeof nl_msg) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;

}
static int 
set_state (char *dev) {


    // NETLINK request schema ....

    // struct nlmsghdr {
    //    __u32 nlmsg_len;    /* Length of message including header */
    //    __u16 nlmsg_type;   /* Type of message content */
    //    __u16 nlmsg_flags;  /* Additional flags */
    //    __u32 nlmsg_seq;    /* Sequence number */
    //    __u32 nlmsg_pid;    /* Sender port ID */
    //  };

    //  +

    //  struct ifinfomsg {
    //      unsigned char  ifi_family; /* AF_UNSPEC */
    //      unsigned short ifi_type;   /* Device type */
    //      int            ifi_index;  /* Interface index */
    //      unsigned int   ifi_flags;  /* Device flags  */
    //      unsigned int   ifi_change; /* change mask */
    //   };

    // ... NETLINK request schema in C-struct  ....
    struct {
        struct nlmsghdr  header;
        struct ifinfomsg payload;
    } nl_msg;

    // Init memory
    ZERO(&nl_msg, sizeof(nl_msg));

    // Define the NETLINK header
    nl_msg.header.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nl_msg.header.nlmsg_flags = NLM_F_REQUEST;
    nl_msg.header.nlmsg_type  = RTM_NEWLINK;
    // Define the NETLINK ROUTE header
    nl_msg.payload.ifi_index  = (int) if_nametoindex(dev);
    nl_msg.payload.ifi_flags  = IFF_UP;
    nl_msg.payload.ifi_change = 1;

    // Have a new socket
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(fd < 0) {
        return -1;
    }

    // Send the nl_msg
    ssize_t n = send(fd, &nl_msg, nl_msg.header.nlmsg_len, 0x00);
    if(n < sizeof nl_msg) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
static int 
set_rtng (char *dev, char *addr, int prefx) {

    // Address attribute buffer
    struct in_addr raddr;
    // Interface as dev
    unsigned int idx = if_nametoindex(dev);

    struct {
        struct nlmsghdr   header;
        struct rtmsg      payload;
        char   attributes [
                ATTRIBUTE_SIZE(sizeof(unsigned int))   +
                ATTRIBUTE_SIZE(sizeof(struct in_addr))];
    } nl_msg;

    // Init memory
    ZERO(&nl_msg,   sizeof(nl_msg));
    ZERO(&raddr, sizeof(struct in_addr));

    // Define the NETLINK header
    nl_msg.header.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    nl_msg.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    nl_msg.header.nlmsg_type  = RTM_NEWROUTE;
    // Define the NETLINK ROUTE header
    nl_msg.payload.rtm_family   = AF_INET;
    nl_msg.payload.rtm_table    = RT_TABLE_MAIN;
    nl_msg.payload.rtm_scope    = RT_SCOPE_UNIVERSE;
    nl_msg.payload.rtm_protocol = RTPROT_BOOT;
    nl_msg.payload.rtm_type     = RTN_UNICAST;
    nl_msg.payload.rtm_dst_len  = prefx;

    // Make address from presentation layout to network layout
    inet_pton(AF_INET, addr, &raddr);
    add_att(
            &nl_msg,
            &raddr,
            sizeof(struct in_addr),
            RTA_DST,
            nl_msg.header.nlmsg_len +
            ATTRIBUTE_SIZE(sizeof(unsigned int)) +
            ATTRIBUTE_SIZE(sizeof(struct in_addr)));
    add_att(
            &nl_msg,
            &idx,
            sizeof(unsigned int),
            RTA_OIF,
            nl_msg.header.nlmsg_len +
                ATTRIBUTE_SIZE(sizeof(unsigned int)) +
                    ATTRIBUTE_SIZE(sizeof(struct in_addr)));

    // Have a new socket
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(fd < 0) {
        return -1;
    }
    // Send the nl_msg
    ssize_t bytes_sent = send(fd, &nl_msg, nl_msg.header.nlmsg_len, 0x00);
    if(bytes_sent < sizeof nl_msg) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int
prefix (char *id) {

    unsigned int n, m;
    n   = from_ascii_to_int(id);
    m   = 0;
    for(; n>0; n=n>>1)
        if (n & 1)
            m++;
    return m;
}
static struct in_addr
gen_ips (char *id, char *mask) {

    FILE *file;
    int i;

    unsigned int net;
    unsigned int hosts;

    struct in_addr in;
    struct in_addr ip;

    if((file = fopen("server/ips.dat", "w")) == NULL) {
        ip.s_addr = 0;
        return ip;
    }

    net = from_ascii_to_int(id);
    hosts = (1 << (32 - prefix(mask))) - 2;
    for(i=1; i<=hosts; i++) {
        in.s_addr = htonl(net) + htonl(i);
        if(i == 1) {
            ip.s_addr = htonl(net) + htonl(i);
            fprintf(file, "%s %s %d\n", inet_ntoa(in), mask, 0);
        } else { 
            fprintf(file, "%s %s %d\n", inet_ntoa(in), mask, 1);
        }
    }
    fclose(file);
    return ip;
}

int
main (int argc, char **argv) {

    int i;
    int res;
    int max;
    
    int cs;
    int ss;
    int len;
    int n;
    int in;

    int  tun;
    char dev [] = "martina";

    struct in_addr ip;
    struct Connection  cconn [MAX_CLIENTS];
    struct sockaddr_in cin;
    char buf [1024];

    fd_set readfds;

    // <program_name> <pnet_id> <pmask> <rnet> <rmask>
    if(argc != 5) 
        goto args_error;
    fprintf(stdout, "[+] Private  Network ID: %s %s\n", argv[1], argv[2]);
    fprintf(stdout, "[+] Remote   Network ID: %s %s\n", argv[3], argv[4]);
    if((ip.s_addr = gen_ips(argv[1], argv[2]).s_addr) == 0)
        goto end;

    ss = start_service (VNP_PORT);
    if (ss < 0)
        exit(EXIT_FAILURE);

    // Setup TUN interface
    if((tun = tun_alloc(dev)) < 0)
        goto tun_error;
    if((res = set_addr(dev, inet_ntoa(ip), 24)) < 0)
        goto tun_error_config;
    if((res = set_state(dev)) < 0)
        goto tun_error_config;

    len = sizeof (cin);
    ZERO(cconn, MAX_CLIENTS * sizeof(struct Connection));

    for(;;) {

        FD_ZERO (&readfds);
        FD_SET  (ss,  &readfds);
        FD_SET  (tun, &readfds);
        max = ss > tun ? ss : tun;
        max = init_fds(cconn, max, &readfds);
        res = select(max + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(ss, &readfds)) {

            cs = accept (ss, (struct sockaddr *) &cin, &len);
            printf("%d\n", cs);
            if (cs < 0) 
                exit(EXIT_FAILURE);

            fprintf(stdout, "   [+] New connection:");
            fprintf(stdout, " - Addr: %s", inet_ntoa (cin.sin_addr));
            fprintf(stdout, " - Port: %u\n", ntohs(cin.sin_port));

            if(client_authentication(cs, cconn) <= 0) {
                fprintf(stdout, "   [+] End connection:");
                fprintf(stdout, " - Addr: %s", inet_ntoa (cin.sin_addr));
                fprintf(stdout, " - Port: %u\n", ntohs(cin.sin_port));
                close(cs);
            }
        } else if (FD_ISSET(tun, &readfds)) {
            handle_tun(tun, argv[3], argv[4], cconn);
        } else {
            for (i=0; i<MAX_CLIENTS; i++) {
                if (FD_ISSET(cconn[i].cs, &readfds)) 
                    handle_cs(&cconn[i].cs, cconn[i].cin, argv[3], argv[4], tun);
            }
        }
    }

end:
    close(ss);
    return 0;

args_error:
    fprintf(stdout, "[-] Invalid arguments\n");
    return 0;    
tun_error:
    fprintf(stdout, "[-] Couldn't create a new TUN interface\n");
    close(ss); 
    return 0;
tun_error_config:
    fprintf(stdout, "[-] Couldn't config TUN interface\n");
    close(tun);
    close(ss); 
    return 0;

}