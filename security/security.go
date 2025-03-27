package security

/*
#cgo LDFLAGS: -lnids -lpcap -lnet

#include <nids.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct scan
{
    u_int addr;
    unsigned short port;
    u_char flags;
};

struct host
{
    struct host *next;
    struct host *prev;
    u_int addr;
    int modtime;
    int n_packets;
    struct scan *packets;
};

struct ip_header
{
    #if defined(WORDS_BIGENDIAN)
        unsigned int ip_v: 4, ip_hl: 4;
    #else
        unsigned int ip_hl: 4, ip_v: 4;
    #endif
    unsigned int ip_tos;
    unsigned char ip_len;
    unsigned char ip_id;
    unsigned char ip_off;
    unsigned int ip_ttl;
    unsigned int ip_p;
    unsigned char ip_csum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcp_header
{
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned short th_seq;
    unsigned short th_ack;
    #ifdef WORDS_BIGENDIAN
        unsigned int th_off: 4,
        th_x2: 4;
    #else
        unsigned int th_x2: 4,
        th_off: 4;
    #endif
    unsigned int th_flags;
    unsigned char th_win;
    unsigned char th_sum;
    unsigned char th_urp;
};

extern void NidsSysLog(int type, int errnum, struct ip_header *iph, void *data);

static void run(char* dev) {
	nids_params.device = dev;
	nids_params.syslog = NidsSysLog;

	if (!nids_init()) {
		printf("nids_init error: %s\n", nids_errbuf);
		return;
	}

	nids_run();
}
*/
import "C"
import (
	"fmt"
	"github/EnderCHX/websafe-go/log"
	"net"
	"unsafe"

	"go.uber.org/zap"
)

var logger *zap.Logger

//export NidsSysLog
func NidsSysLog(type_ C.int, errnum C.int, iph *C.struct_ip_header, data *C.void) {
	scan_number := 0
	flagsand, flagsor := C.uchar(255), C.u_char(0)
	if type_ == C.NIDS_WARN_IP {
		if errnum != C.NIDS_WARN_IP_HDR {
			source_ip := net.IPv4(byte(iph.ip_src.s_addr), byte(iph.ip_src.s_addr>>8), byte(iph.ip_src.s_addr>>16), byte(iph.ip_src.s_addr>>24))
			dest_ip := net.IPv4(byte(iph.ip_dst.s_addr), byte(iph.ip_dst.s_addr>>8), byte(iph.ip_dst.s_addr>>16), byte(iph.ip_dst.s_addr>>24))
			logger.Info(fmt.Sprintf("%v,packet(apparently from %v to %v", C.nids_warnings[errnum], source_ip, dest_ip))
		} else {
			// logger.Info(fmt.Sprintf("%v", C.nids_warnings[errnum]))
		}
	} else if type_ == C.NIDS_WARN_TCP {
		source_ip := net.IPv4(byte(iph.ip_src.s_addr), byte(iph.ip_src.s_addr>>8), byte(iph.ip_src.s_addr>>16), byte(iph.ip_src.s_addr>>24))
		dest_ip := net.IPv4(byte(iph.ip_dst.s_addr), byte(iph.ip_dst.s_addr>>8), byte(iph.ip_dst.s_addr>>16), byte(iph.ip_dst.s_addr>>24))
		if errnum != C.NIDS_WARN_TCP_HDR {
			logger.Info(fmt.Sprintf("%v,from %v:%v to  %v:%v", C.nids_warnings[errnum],
				source_ip, C.ntohs(((*C.struct_tcp_header)(unsafe.Pointer(data))).th_sport),
				dest_ip, C.ntohs(((*C.struct_tcp_header)(unsafe.Pointer(data))).th_dport)))
		} else {
			// logger.Debug(fmt.Sprintf("%v", errnum))
			// logger.Info(fmt.Sprintf(",from %v to %v", source_ip, dest_ip))
		}
	} else if type_ == C.NIDS_WARN_SCAN {
		scan_number++
		// logger.Info(fmt.Sprintf("-------------  %v  -------------", scan_number))
		logger.Info("-----  发现扫描攻击 -----")
		host_information := (*C.struct_host)(unsafe.Pointer(data))
		scanner_ip := (*C.struct_in_addr)(unsafe.Pointer(&host_information.addr))

		logger.Info(fmt.Sprintf("扫描者的IP地址: %v", C.GoString(C.inet_ntoa(*scanner_ip))))
		logger.Info("被扫描者的IP地址和端口号为:")
		for i := 0; i < int(host_information.n_packets); i++ {
			elemptr := unsafe.Pointer(
				uintptr(unsafe.Pointer(host_information.packets)) +
					uintptr(i)*unsafe.Sizeof(C.struct_scan{}),
			)
			scan := (*C.struct_scan)(elemptr)
			scaned_ip := C.inet_ntoa(*(*C.struct_in_addr)(unsafe.Pointer(&scan.addr)))
			scaned_port := C.ntohs(scan.port)

			flagsand &= scan.flags
			flagsor |= scan.flags

			logger.Info(fmt.Sprintf("%v:%v", C.GoString(scaned_ip), scaned_port))
		}

		if flagsand == flagsor {
			switch flagsand {
			case 0:
				logger.Info("扫描类型为: NULL")
			case 1:
				logger.Info("扫描类型为: FIN")
			case 2:
				logger.Info("扫描类型为: SYN")
			default:
				logger.Info(fmt.Sprintf("标志=0x%x", flagsand))
			}
		} else {
			logger.Info("标志异常")
		}
	} else {
		logger.Info("位置")
	}
}
func Run(dev string) {
	// defer func() {
	// 	if err := recover(); err != nil {
	// 		logger.Error(fmt.Sprintf("%v", err))
	// 	}
	// }()
	logger = log.NewLogger("security.log", "debug")
	logger.Info("开始捕获扫描攻击")
	logger.Info("使用网卡:" + dev)
	C.run(C.CString(dev))
}
