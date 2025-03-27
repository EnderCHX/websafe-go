package ethernet

/*
#cgo LDFLAGS: -lnids -lpcap -lnet

#include <stdio.h>
#include <stdlib.h>
#include <nids.h>
#include <pcap.h>

struct ether_header
{
    u_int8_t ether_dhost[6];

    u_int8_t ether_shost[6];

    u_int16_t ether_type;
};

extern void EthernetCallBack(unsigned char *arg, struct pcap_pkthdr *pkthdr, unsigned char *packet);

static void run(char* dev, char* filter) {
	char errbuf[1024];
	pcap_t* device = pcap_open_live(dev,65535,1,0,errbuf);

	if (filter != "") {
		struct bpf_program bpf_filter;
		pcap_compile(device, &bpf_filter, filter, 0, 0);
		pcap_setfilter(device, &bpf_filter);
	}

	if(!device){
        printf("couldn't open the net device: %s\n",errbuf);
        return;
    }

	pcap_loop(device,-1,(void*)EthernetCallBack, NULL);
}
*/
import "C"
import (
	"fmt"
	"github/EnderCHX/websafe-go/log"
	"unsafe"

	"go.uber.org/zap"
)

var logger *zap.Logger

//export EthernetCallBack
func EthernetCallBack(arg *C.uchar, pkthdr *C.struct_pcap_pkthdr, packet *C.uchar) {
	logger.Info("----------------------------------------------")
	logger.Info("Ethernet")
	ethernet_protocol := (*C.struct_ether_header)(unsafe.Pointer(packet))
	ethernet_type := C.ntohs(ethernet_protocol.ether_type)

	switch ethernet_type {
	case 0x0800:
		logger.Info("IPv4")
	case 0x0806:
		logger.Info("ARP")
	case 0x8035:
		logger.Info("RARP")
	case 0x86dd:
		logger.Info("IPv6")
	default:
		logger.Info("Unknown")
	}
	srcMac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		ethernet_protocol.ether_shost[0], ethernet_protocol.ether_shost[1],
		ethernet_protocol.ether_shost[2], ethernet_protocol.ether_shost[3],
		ethernet_protocol.ether_shost[4], ethernet_protocol.ether_shost[5])
	logger.Info("源MAC地址:" + srcMac)
	dstMac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		ethernet_protocol.ether_dhost[0], ethernet_protocol.ether_dhost[1],
		ethernet_protocol.ether_dhost[2], ethernet_protocol.ether_dhost[3],
		ethernet_protocol.ether_dhost[4], ethernet_protocol.ether_dhost[5])
	logger.Info("目标MAC地址:" + dstMac)
	logger.Info("----------------------------------------------")
}

func RunEthernet(dev, filter string) {
	logger = log.NewLogger("ethernet.log", "debug")
	logger.Info("开始捕获ethernet")
	logger.Info("使用网卡:" + dev + " 过滤规则:" + filter)
	C.run(C.CString(dev), C.CString(filter))
}
