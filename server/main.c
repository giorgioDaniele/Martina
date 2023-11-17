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
    USERNAME, 
    CHALLENGE, 
    RESPONSE, 
    FAILURE, 
    SUCCESS
};

struct Message {
    enum Command cmd;
    char data [DATA_MAX_SIZE + 1];
};

struct Connection {
    int cs;
    struct sockaddr_in cin;
};


typedef struct Connection  Con_t;
typedef struct sockaddr_in Skt_t;
typedef struct Message     Msg_t;
typedef unsigned int       IP_t;
typedef char*              AD_t;
typedef fd_set Set_t;

static int 
init_fds (
    Con_t  *ccon,   // Client Connection object
    int     maxc,   // Clients at most
    Set_t  *rfds) { // Set of readers 

    int cskt;
    int nmax;

    nmax = maxc;
    for(int i=0; i<MAX_CLIENTS; i++) {
        cskt = ccon[i].cs;
        if(cskt > 0)
            FD_SET(cskt, rfds);
        if(cskt > maxc) 
            nmax = cskt;
    }
    return nmax;
}

static void 
regst_cs (
    Con_t  *ccon,   // Client Connection object
    Skt_t   cskt,   // Client socket object
    int     cdes) { // Client socket descriptor

    for (int i=0; i<MAX_CLIENTS; i++) {
        if(ccon[i].cs == 0)  {
            ccon[i].cs  = cdes; 
            ccon[i].cin = cskt;
            break;
        }
    }
    return;
}

static int 
start (
    int port) { // Port number the server listens at

    int s, n;

    Skt_t sskt;

    ZERO (&sskt, sizeof (sskt));
    sskt.sin_family = AF_INET;
    sskt.sin_port   = htons (port);

    sskt.sin_addr.s_addr = htonl (INADDR_ANY);
    s = socket (AF_INET, SOCK_STREAM, 0);

    if (s < 0)
        goto sock_creation;
    n = 1;
    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof (n)) < 0) 
        goto sock_options;
    if (bind (s, (struct sockaddr *) &sskt, sizeof (sskt)) < 0)
        goto sock_binding;
    if (listen (s, 5) < 0) 
        goto sock_listening;

    fprintf(stdout, "[+] Service is up and running\n");
    fprintf(stdout, "    Local Address: %s\n",   inet_ntoa(sskt.sin_addr));
    fprintf(stdout, "    Port:          %u\n\n", ntohs(sskt.sin_port));
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
auth (
    int    cdes,     // Client socket descriptor
    Con_t *cconn) {  // Client soscket object

    FILE  *fdes;
    int    fnd;

    Skt_t cin;
    Msg_t msg;

    char buf   [USERNAME_SIZE + PASSWORD_SIZE + RANDOM_SIZE];
    char usr   [PASSWORD_SIZE + 1];
    char pwd   [USERNAME_SIZE + 1];
    char rnd   [  ] = "ABCDABCDABCDABCD";
    char dgt   [SHA256_DIGEST_LENGTH];

    char  cadd [INET_ADDRSTRLEN];
    char  cmsk [INET_ADDRSTRLEN];

    ZERO(usr, PASSWORD_SIZE + 1);
    ZERO(pwd, PASSWORD_SIZE + 1);
    

    // Receive username
    ZERO(&msg, sizeof(struct Message));
    if (read (cdes, (void*) &msg, sizeof(msg.cmd) + DATA_MAX_SIZE + 1) == 0)
        goto disconneted;

    // Search username
    if((fdes = fopen("server/users.dat", "r")) == NULL)
        goto io_err;
    

    fnd = 0;
    while (fscanf(fdes, "%s %s\n", usr, pwd) == 2) {
        if(strcmp(msg.data, usr) == 0) {
            fnd = 1;
            break;
        }
    }
    fclose(fdes);

    if(!fnd) 
        goto failure;   
    
    // Looup for an IP
    if((fdes = fopen("server/ips.dat", "r")) == NULL)
        goto io_err;
    
    fnd = 0;
    while (fscanf(fdes, "%s %s %d\n", cadd, cmsk, &fnd) == 3) {
        if(fnd)
            break;
    }
    fclose(fdes);
    if(!fnd) 
        goto failure;

    ZERO    (buf, USERNAME_SIZE + PASSWORD_SIZE + RANDOM_SIZE);
    MOVE    (buf, usr, strlen(usr), 0x00);
    MOVE    (buf, pwd, strlen(pwd), strlen(usr));
    MOVE    (buf, rnd,   strlen(rnd),   strlen(usr) + strlen(pwd));
    SHA256  (buf, strlen(usr) + strlen(pwd) + strlen(rnd), dgt);   // SHA256 ([username | password | random])

    // Send challenge
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = CHALLENGE;
    memcpy(msg.data, rnd, strlen(rnd) + 1);
    write (cdes, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);

    // Receive response
    ZERO(&msg, sizeof(struct Message));
    if (read (cdes, (void*) &msg, sizeof(msg.cmd) + DATA_MAX_SIZE + 1) == 0)
        goto disconneted;

    dgt      [SHA256_DIGEST_LENGTH] = '\0';
    msg.data [SHA256_DIGEST_LENGTH] = '\0';

    if(strcmp(dgt, msg.data) == 0)
        goto success;
    else
        goto failure;

io_err:
    fprintf(stdout, "[-] Couldn't open file\n");
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = FAILURE;
    write (cdes, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);
    return 0;

failure:
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = FAILURE;
    write (cdes, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);
    return 0;

success:
    // Register new client
    ZERO(&cin, sizeof(struct sockaddr_in));
    cin.sin_addr.s_addr = inet_addr(cadd);
    regst_cs(cconn, cin, cdes);
    ZERO(&msg, sizeof(struct Message));
    msg.cmd = SUCCESS;
    sprintf(msg.data, "%s %s", cadd, cmsk);
    write (cdes, (const void*) &msg, sizeof(msg.cmd) + strlen(msg.data) + 1);
    return 1;

disconneted:
    return -1;
}

static int 
is_ipv4 (
    char * pkt) { // Raw packet
    return ((pkt[0] & 0xF0) >> 4) == 0x04;
}

static int 
fatoi (
    AD_t ad) { // The address to convert to IP as value

    unsigned int fst;
    unsigned int snd;
    unsigned int thd;
    unsigned int fth;

    sscanf(ad, "%u.%u.%u.%u", &fst, &snd, &thd, &fth);
    return IP_ADDRESS_FROM_OCTETS(fst, snd, thd, fth);
}

static void 
fitoa (
    IP_t  ip,   // The address as value
    AD_t  ad) { // The buffer to fill with ASCII
    sprintf(ad, "%u.%u.%u.%u",
            (ip >> 24)  & 0xFF,
            (ip >> 16)  & 0xFF,
            (ip >> 8)   & 0xFF,
            ip          & 0xFF);
    return;
}

static int
is_to_net (
    IP_t net, 
    IP_t msk, 
    IP_t dst) {

    if((net & msk) == (dst & msk)) 
        return 1;
    return 0;
}

// static void 
// dump_hex_message (
//     const char * buf, 
//     int size) {

//     for(int i=0; i<size; i++) {
//         printf("0x%02x ", (unsigned char) buf[i]);
//         if(i % 12 == 0 && i) {
//             printf("\n");
//         }
//     }
//     printf("\n");
//     return;
// }

static int
prefix (
    AD_t id) { // The ASCII of a network ID

    unsigned int n, m;
    n   = fatoi(id);
    m   = 0;
    for(; n>0; n=n>>1)
        if (n & 1)
            m++;
    return m;
}

static void 
handle_cs (
    int   *cdes,   // Client socket descriptor
    Skt_t  cskt,   // Client socket object
    AD_t   rnet,   // Remote network ID
    AD_t   rmsk,   // Remote network mask
    int    tdes) { // TUN interface descriptor

    FILE *fdes;
    int   fnd;

    int   nread;
    char  buffr [MSS];
    char  fline [INET6_ADDRSTRLEN * 2 + 1];
    char  cadd  [INET_ADDRSTRLEN];
    char  cmsk  [INET_ADDRSTRLEN];
    char  tadd  [INET_ADDRSTRLEN];
    unsigned int curr;

    // Read from the client socket
    if ((nread = read(*cdes , buffr, MSS)) == 0) { // If no payload, the client has exited the connection
    
        fprintf(stdout, "   [+] End connection:");
        fprintf(stdout, " - Addr: %s",   inet_ntoa(cskt.sin_addr));
        fprintf(stdout, " - Port: %u\n", ntohs(cskt.sin_port));
        close(*cdes);         // Close the connection on the server side

        // Cleanup the IP assignment file
        if((fdes = fopen("server/ips.dat", "r")) == NULL)
            goto io_err;

        fitoa((unsigned int)cskt.sin_addr.s_addr, tadd);
        fnd  = 0;
        curr = 0;
        while ((nread = read(fdes, fline, sizeof(fline))) > 0) {
            if (sscanf(fline, "%s %s %d", cadd, cmsk, &fnd) == 3) {
                if(strcmp(cadd, tadd) == 0) {
                    // Move the file pointer to the beginning of the line
                    lseek(fdes, curr, SEEK_SET);
                    // Update the number in the same position
                    dprintf(fdes, "%s %s %d", cadd, cmsk, 1);
                    // Move the file pointer back to the end of the line
                    lseek(fdes, nread - sizeof(int), SEEK_CUR);    
                }
            } else {
                fprintf(stdout, "Invalid line format: %s", fline);
            } // Move the file pointer to the next line
            curr = lseek(fdes, 0, SEEK_CUR);
        }
    } else { // Otherwise, the client has sent something to forward
        if(is_ipv4(buffr)) { // If this is an IPv4 packet
            if(is_to_net(
                fatoi(rnet), 
                    fatoi(rmsk), 
                        ntohl(*(unsigned int*)(buffr + 16)))) { // If it is for the remote network 
                            write (tdes, (const void*) buffr, nread); // Write the TUN interface
                }
        }
    }
    return;

io_err:
    fprintf(stdout, "[-] Couldn't open file\n");
    return;

}

static void 
handle_tun (
    int    tdes,    // TUN interface descriptor
    AD_t   rnet,    // Remote network
    AD_t   rmsk,    // Remoet network mask
    Con_t *ccon) {  // Client connection object

    int nread, i;

    IP_t src;
    IP_t dst;
    char buf [MSS];

    if ((nread = read(tdes , buf, MSS)) == 0) { /* TODO */} 
    else {
        if(is_ipv4(buf)) {
            src = ntohl(*(unsigned int*)(buf + 12));
            dst = *(unsigned int*)(buf + 16);
            if(is_to_net(fatoi(rnet), fatoi(rmsk), src)) {
                for(i=0; i<MAX_CLIENTS; i++) {
                    if(ccon[i].cin.sin_addr.s_addr == dst) {
                        write (ccon[i].cs, (const void*) buf, nread);
                        break;
                    }
                }
            }
        }
    }
    return;
}


static int 
tun_alloc(
    char *dev) {

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
add_att (
    void *req, 
    void *attval, 
    int   attlen, 
    int   attype, 
    int   maxsz) {

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
set_addr (
    char *dev, 
    char *addr, 
    int prefx) {

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
set_state (
    char *dev) {


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
set_rtng (
    char *dev, 
    char *addr, 
    int prefx) {

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

// File configuaration
static struct in_addr 
gen_ips (
    char *id, 
    char *mask) {

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

    net = fatoi(id);
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

// Main
int 
main (
    int argc, 
    char **argv) {

    // Socket related variables
    int  cs;
    int  ss;
    int  res;

    // TUN related variables
    int  tun;
    char dev [] = "martina";

    // Select syscall stuff
    Set_t  reads;
    int    max;

    // Generic
    int i;
    int len;
    
    struct in_addr ip;
    Skt_t  cin;
    Con_t  cconn [MAX_CLIENTS];

    // <program_name> <pnet_id> <pmask> <rnet> <rmask>
    if(argc != 5) 
        goto args_error;

    fprintf(stdout, "[+] Private  Network ID: %s %s\n", argv[1], argv[2]);
    fprintf(stdout, "[+] Remote   Network ID: %s %s\n", argv[3], argv[4]);

    ss = -1;
    if((ip.s_addr = gen_ips(argv[1], argv[2]).s_addr) == 0)
        goto end;

    ss = start (VNP_PORT);
    if (ss < 0)
        exit(EXIT_FAILURE);

    // Setup TUN interface
    if((tun = tun_alloc(dev)) < 0)
        goto tun_error;
    if((res = set_addr(dev, argv[1], prefix(argv[2]))) < 0)
        goto tun_error_config;
    if((res = set_state(dev)) < 0)
        goto tun_error_config;

    len = sizeof (struct sockaddr_in);
    ZERO(cconn, MAX_CLIENTS * sizeof(struct Connection));

    for(;;) {

        FD_ZERO (&reads);
        FD_SET  (ss,  &reads);
        FD_SET  (tun, &reads);

        max = ss > tun ? ss : tun;
        max = init_fds(cconn, max, &reads);
        res = select(max + 1, &reads, NULL, NULL, NULL);


        if (FD_ISSET(ss, &reads)) {

            cs = accept (ss, (struct sockaddr *) &cin, &len);
            if (cs < 0) 
                exit(EXIT_FAILURE);

            fprintf(stdout, "   [+] New connection:");
            fprintf(stdout, " - Addr: %s", inet_ntoa (cin.sin_addr));
            fprintf(stdout, " - Port: %u\n", ntohs(cin.sin_port));

            if(auth(cs, cconn) <= 0) {
                fprintf(stdout, "   [+] End connection:");
                fprintf(stdout, " - Addr: %s", inet_ntoa (cin.sin_addr));
                fprintf(stdout, " - Port: %u\n", ntohs(cin.sin_port));
                close(cs);
            }
        } 

        else if (FD_ISSET(tun, &reads)) {
            handle_tun(tun, argv[3], argv[4], cconn);
        }
        
        else {
            for (i=0; i<MAX_CLIENTS; i++) {
                if (FD_ISSET(cconn[i].cs, &reads)) 
                    handle_cs(&cconn[i].cs, cconn[i].cin, argv[3], argv[4], tun);
            }
        }
    }

end:
    if(ss > 0)
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