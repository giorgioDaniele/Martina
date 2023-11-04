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

#define PASSWORD_SIZE 30
#define USERNAME_SIZE 30
#define DATA_MAX_SIZE 512
#define RANDOM_SIZE   16
#define VNP_PORT      8888
#define MSS           1460

// It sets all the buffer to zero
#define ZERO(ptr, size)\
    memset(ptr, 0, size)
// It copies a buffer into another
#define MOVE(dst, src, size, offset)\
    memmove(dst + offset, src, size)
// It does return the address of the attributes section
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
connect_server (char *host, int port) {

    int s;
    struct sockaddr_in sa;

    s = socket (AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        goto sock_creation;

    ZERO (&sa, sizeof (sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons (0); /* Tells OS to choose a port */
    sa.sin_addr.s_addr = htonl (INADDR_ANY); /* Tells OS to choose IP addr */

    if (bind (s, (struct sockaddr *) &sa, sizeof (sa)) < 0)
        goto sock_binding;

    sa.sin_port        = htons (VNP_PORT);
    sa.sin_addr.s_addr = inet_addr(host);

    if (connect (s, (struct sockaddr *) &sa, sizeof (sa)) < 0)
        goto sock_connecting;
    return s;

sock_creation:
    fprintf(stderr, "[-] Socket creation has failed\n");
    return -1;
sock_binding:
    fprintf(stderr, "[-] Socket creation has failed\n");
    close (s);
    return -1;
sock_connecting:
    fprintf(stderr, "[-] Connection to server has failed\n");
    close (s);
    return -1;
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

int
main (int argc, char **argv) {

    int  cs, n;
    int  res;
    int  tun;
    char dev [] = "martina";
    struct Message msg;

    fd_set readfds;
    int    max;
    char   buf [MSS];

    unsigned int src;
    unsigned int dst;

    char rnet     [] = "192.168.200.0";
    char rmask    [] = "255.255.255.0";
    char ip      [INET_ADDRSTRLEN];
    char mask    [INET_ADDRSTRLEN];

    char username  [PASSWORD_SIZE + 1];
    char password  [USERNAME_SIZE + 1];
    char buffer    [USERNAME_SIZE + PASSWORD_SIZE + RANDOM_SIZE];
    char digest    [SHA256_DIGEST_LENGTH];

    fprintf (stdout, "#### Martina client ####\n");
    fprintf (stdout, "Enter your username: ");
    fscanf  (stdin, "%s", username);
    fprintf (stdout, "Enter your password: ");
    fscanf  (stdin, "%s", password);

    cs = connect_server ("10.0.0.2", VNP_PORT);
    if (cs < 0)
        exit(EXIT_FAILURE);

    // Send username
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = USERNAME;
    memcpy(msg.data, username, strlen(username) + 1);
    write (cs, (const void*) & msg, sizeof(msg.cmd) + strlen(msg.data) + 1);

    // Receive response
    ZERO (&msg, sizeof(struct Message));
    read (cs, (void*) &msg, sizeof(msg.cmd) + DATA_MAX_SIZE + 1);
    if(msg.cmd == FAILURE) 
        goto invalid_username;

    ZERO    (buffer, USERNAME_SIZE + PASSWORD_SIZE + RANDOM_SIZE);
    MOVE    (buffer, username, strlen(username), 0x00);
    MOVE    (buffer, password, strlen(password), strlen(username));
    MOVE    (buffer, msg.data, strlen(msg.data), strlen(username) + strlen(password));
    SHA256  (buffer, strlen(username) + strlen(password) + strlen(msg.data), digest);   // SHA256 ([username | password | random])

    // Send reponse
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = RESPONSE;
    memcpy(msg.data, digest, SHA256_DIGEST_LENGTH);
    write (cs, (const void*) & msg, sizeof(msg.cmd) + strlen(msg.data) + 1);

    // Receive result
    ZERO(&msg, sizeof(struct Message));
    read (cs, (void*) &msg, sizeof(msg.cmd) + DATA_MAX_SIZE + 1);
    if(msg.cmd == FAILURE)
        goto invalid_password;

    // Get IP address and netmask
    sscanf(msg.data, "%s %s", ip, mask);

    // Setup TUN interface
    if((tun = tun_alloc(dev)) < 0)
        goto tun_error;
    if((res = set_addr(dev, ip, prefix(mask))) < 0)
        goto tun_error_config;
    if((res = set_state(dev)) < 0)
        goto tun_error_config;
    if((res = set_rtng(dev, rnet, 24)) < 0)
        goto tun_error_config; 

    printf("Client has been configured!\n");

    for(;;) {

        FD_ZERO (&readfds);
        FD_SET  (cs,  &readfds);
        FD_SET  (tun, &readfds);
        max = cs > tun ? cs : tun;

        res = select(max + 1, &readfds, NULL, NULL, NULL);
        if (FD_ISSET(tun, &readfds)) { // Receiving traffic from TUN interface
            n = read (tun, (void*) &buf, MSS);
            if(is_ipv4(buf)) { // If it is an IPv4 packet
                dst = ntohl(*(unsigned int*)(buf + 16));
                if(belongs_to_net(from_ascii_to_int(rnet), from_ascii_to_int(rmask), dst))
                    write (cs, (const void*) buf, n); // Send to the VPN server

            }
        }
        if (FD_ISSET(cs, &readfds)) { // Receiving traffic from VPN server
            n = read (cs, (void*) &buf, MSS);
            if(is_ipv4(buf)) { // If it is an IPv4 packet
                src = ntohl(*(unsigned int*)(buf + 12));
                write (tun, (const void*) buf, n); // Send to the TUN interface
            }
        }
    }

    close(cs);
    return 0;

invalid_username:
    fprintf(stdout, "[-] Invalid username, %s does not exists\n", username);
    close(cs);
    return 0;
invalid_password:
    fprintf(stdout, "[-] Invalid password for username %s\n", username);
    close(cs);
    return 0;
tun_error:
    fprintf(stdout, "[-] Couldn't create a new TUN interface\n");
    close(cs); 
    return 0;
tun_error_config:
    fprintf(stdout, "[-] Couldn't config TUN interface\n");
    close(tun);
    close(cs); 
    return 0;
}