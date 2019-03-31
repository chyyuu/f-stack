#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "ff_config.h"
#include "ff_api.h"

#include "stats.h"
#include "log.h"
#include "memory.h"
#include "device.h"

#define MAX_EVENTS 512

// number of packets sent simultaneously to our driver
static const uint32_t BATCH_SIZE = 64;

// excluding CRC (offloaded by default)
#define PKT_SIZE 60

/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;

char html[] = 
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack\r\n"
"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 439\r\n"
"Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
"Connection: keep-alive\r\n"
"Accept-Ranges: bytes\r\n"
"\r\n"
"<!DOCTYPE html>\r\n"
"<html>\r\n"
"<head>\r\n"
"<title>Welcome to F-Stack!</title>\r\n"
"<style>\r\n"
"    body {  \r\n"
"        width: 35em;\r\n"
"        margin: 0 auto; \r\n"
"        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
"    }\r\n"
"</style>\r\n"
"</head>\r\n"
"<body>\r\n"
"<h1>Welcome to F-Stack!</h1>\r\n"
"\r\n"
"<p>For online documentation and support please refer to\r\n"
"<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
"\r\n"
"<p><em>Thank you for using F-Stack.</em></p>\r\n"
"</body>\r\n"
"</html>";

int loop(void *arg)
{
    /* Wait for events to happen */
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;

        /* Handle disconnect */
        if (event.flags & EV_EOF) {
            /* Simply close socket */
            ff_close(clientfd);
        } else if (clientfd == sockfd) {
            int available = (int)event.data;
            do {
                int nclientfd = ff_accept(sockfd, NULL, NULL);
                if (nclientfd < 0) {
                    printf("ff_accept failed:%d, %s\n", errno,
                        strerror(errno));
                    break;
                }

                /* Add to event list */
                EV_SET(&kevSet, nclientfd, EVFILT_READ, EV_ADD, 0, 0, NULL);

                if(ff_kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0) {
                    printf("ff_kevent error:%d, %s\n", errno,
                        strerror(errno));
                    return -1;
                }

                available--;
            } while (available);
        } else if (event.filter == EVFILT_READ) {
            char buf[256];
            size_t readlen = ff_read(clientfd, buf, sizeof(buf));

            ff_write(clientfd, html, sizeof(html));
        } else {
            printf("unknown event: %8.8X\n", event.flags);
        }
    }
}

static const uint8_t pkt_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // src MAC
        0x08, 0x00,                         // ether type: IPv4
        0x45, 0x00,                         // Version, IHL, TOS
        (PKT_SIZE - 14) >> 8,               // ip len excluding ethernet, high byte
        (PKT_SIZE - 14) & 0xFF,             // ip len exlucding ethernet, low byte
        0x00, 0x00, 0x00, 0x00,             // id, flags, fragmentation
        0x40, 0x11, 0x00, 0x00,             // TTL (64), protocol (UDP), checksum
        0x0A, 0x00, 0x00, 0x01,             // src ip (10.0.0.1)
        0x0A, 0x00, 0x00, 0x02,             // dst ip (10.0.0.2)
        0x00, 0x2A, 0x05, 0x39,             // src and dst ports (42 -> 1337)
        (PKT_SIZE - 20 - 14) >> 8,          // udp len excluding ip & ethernet, high byte
        (PKT_SIZE - 20 - 14) & 0xFF,        // udp len exlucding ip & ethernet, low byte
        0x00, 0x00,                         // udp checksum, optional
        'i', 'x', 'y'                       // payload
        // rest of the payload is zero-filled because mempools guarantee empty bufs
};

// calculate a IP/TCP/UDP checksum
static uint16_t calc_ip_checksum(uint8_t* data, uint32_t len) {
    if (len % 1) error("odd-sized checksums NYI"); // we don't need that
    uint32_t cs = 0;
    for (uint32_t i = 0; i < len / 2; i++) {
        cs += ((uint16_t*)data)[i];
        if (cs > 0xFFFF) {
            cs = (cs & 0xFFFF) + 1; // 16 bit one's complement
        }
    }
    return ~((uint16_t) cs);
}


static struct mempool* init_mempool() {
    const int NUM_BUFS = 2048;
    struct mempool* mempool = memory_allocate_mempool(NUM_BUFS, 0);
    // pre-fill all our packet buffers with some templates that can be modified later
    // we have to do it like this because sending is async in the hardware; we cannot re-use a buffer immediately
    struct pkt_buf* bufs[NUM_BUFS];
    for (int buf_id = 0; buf_id < NUM_BUFS; buf_id++) {
        struct pkt_buf* buf = pkt_buf_alloc(mempool);
        buf->size = PKT_SIZE;
        memcpy(buf->data, pkt_data, sizeof(pkt_data));
        *(uint16_t*) (buf->data + 24) = calc_ip_checksum(buf->data + 14, 20);
        bufs[buf_id] = buf;
    }
    // return them all to the mempool, all future allocations will return bufs with the data set above
    for (int buf_id = 0; buf_id < NUM_BUFS; buf_id++) {
        pkt_buf_free(bufs[buf_id]);
    }

    return mempool;
}

struct ixy_device* ixy_dev;
struct mempool* ixy_mempool;

int main(int argc, char * argv[])
{

    if (argc != 2) {
        printf("Usage: %s <pci bus id>\n", argv[0]);
        return 1;
    }

    ixy_mempool = init_mempool();
    ixy_dev = ixy_init(argv[1], 1, 1);

    uint64_t last_stats_printed = monotonic_time();
    uint64_t counter = 0;
    struct device_stats stats_old, stats;
    stats_init(&stats, ixy_dev);
    stats_init(&stats_old, ixy_dev);
    uint32_t seq_num = 0;

    // array of bufs sent out in a batch
    struct pkt_buf* bufs[BATCH_SIZE];

    pkt_buf_alloc_batch(ixy_mempool, bufs, BATCH_SIZE);

    ff_init(argc, argv);

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("ff_socket failed\n");
        exit(1);
    }

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed\n");
        exit(1);
    }

    ret = ff_listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed\n");
        exit(1);
    }

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);

    assert((kq = ff_kqueue()) > 0);

    /* Update kqueue */
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

    ff_run(loop, NULL);
    return 0;
}








//static const uint8_t pkt_data[] = {
//        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
//        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // src MAC
//        0x08, 0x00,                         // ether type: IPv4
//        0x45, 0x00,                         // Version, IHL, TOS
//        (PKT_SIZE - 14) >> 8,               // ip len excluding ethernet, high byte
//        (PKT_SIZE - 14) & 0xFF,             // ip len exlucding ethernet, low byte
//        0x00, 0x00, 0x00, 0x00,             // id, flags, fragmentation
//        0x40, 0x11, 0x00, 0x00,             // TTL (64), protocol (UDP), checksum
//        0x0A, 0x00, 0x00, 0x01,             // src ip (10.0.0.1)
//        0x0A, 0x00, 0x00, 0x02,             // dst ip (10.0.0.2)
//        0x00, 0x2A, 0x05, 0x39,             // src and dst ports (42 -> 1337)
//        (PKT_SIZE - 20 - 14) >> 8,          // udp len excluding ip & ethernet, high byte
//        (PKT_SIZE - 20 - 14) & 0xFF,        // udp len exlucding ip & ethernet, low byte
//        0x00, 0x00,                         // udp checksum, optional
//        'i', 'x', 'y'                       // payload
//        // rest of the payload is zero-filled because mempools guarantee empty bufs
//};




//int main(int argc, char* argv[]) {
//    if (argc != 2) {
//        printf("Usage: %s <pci bus id>\n", argv[0]);
//        return 1;
//    }
//
//    struct mempool* mempool = init_mempool();
//    struct ixy_device* dev = ixy_init(argv[1], 1, 1);
//
//    uint64_t last_stats_printed = monotonic_time();
//    uint64_t counter = 0;
//    struct device_stats stats_old, stats;
//    stats_init(&stats, dev);
//    stats_init(&stats_old, dev);
//    uint32_t seq_num = 0;
//
//    // array of bufs sent out in a batch
//    struct pkt_buf* bufs[BATCH_SIZE];
//
//    // tx loop
//    while (true) {
//        // we cannot immediately recycle packets, we need to allocate new packets every time
//        // the old packets might still be used by the NIC: tx is async
//        pkt_buf_alloc_batch(mempool, bufs, BATCH_SIZE);
//        for (uint32_t i = 0; i < BATCH_SIZE; i++) {
//            // packets can be modified here, make sure to update the checksum when changing the IP header
//            *(uint32_t*)(bufs[i]->data + PKT_SIZE - 4) = seq_num++;
//        }
//        // the packets could be modified here to generate multiple flows
//        ixy_tx_batch_busy_wait(dev, 0, bufs, BATCH_SIZE);
//
//        // don't check time for every packet, this yields +10% performance :)
//        if ((counter++ & 0xFFF) == 0) {
//            uint64_t time = monotonic_time();
//            if (time - last_stats_printed > 1000 * 1000 * 1000) {
//                // every second
//                ixy_read_stats(dev, &stats);
//                print_stats_diff(&stats, &stats_old, time - last_stats_printed);
//                stats_old = stats;
//                last_stats_printed = time;
//            }
//        }
//        // track stats
//    }
//    return 0;
//}

