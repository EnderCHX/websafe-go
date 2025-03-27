package http

/*
#cgo LDFLAGS: -lnids -lpcap -lnet

#include <nids.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern void TcpCallBack(struct tcp_stream *tc, void **param);

static void start_nids(char* dev, char* filter) {
	nids_params.device = dev;
	if (filter != "") {
		nids_params.pcap_filter = filter;
	}

	struct nids_chksum_ctl temp;
	temp.netaddr = 0;
	temp.mask = 0;
	temp.action = 1;
	nids_register_chksum_ctl(&temp, 1);


	if (!nids_init()) {
		return;
	}

	nids_register_tcp(TcpCallBack);

	nids_run();
}
*/
import "C"

import (
	"fmt"
	"github/EnderCHX/websafe-go/log"
	"strings"

	"net"
	"unsafe"

	"go.uber.org/zap"
)

const (
	NIDS_JUST_EST  = 1
	NIDS_DATA      = 2
	NIDS_CLOSE     = 3
	NIDS_RESET     = 4
	NIDS_TIMED_OUT = 5
	NIDS_EXITING   = 6 /* nids is exiting; last chance to get data */
)

var logger *zap.Logger

//export TcpCallBack
func TcpCallBack(tc *C.struct_tcp_stream, param **C.void) {
	saddr := net.IPv4(byte(tc.addr.saddr), byte(tc.addr.saddr>>8), byte(tc.addr.saddr>>16), byte(tc.addr.saddr>>24))
	daddr := net.IPv4(byte(tc.addr.daddr), byte(tc.addr.daddr>>8), byte(tc.addr.daddr>>16), byte(tc.addr.saddr>>24))

	logger.Info(fmt.Sprintf("%v:%v <----> %v:%v", saddr, tc.addr.source, daddr, tc.addr.dest))

	if tc.nids_state == C.char(NIDS_JUST_EST) {
		tc.client.collect++
		tc.server.collect++

		logger.Info("==============================================")
		logger.Info(fmt.Sprintf("%v 建立连接...", daddr))
	}

	if tc.nids_state == C.char(NIDS_CLOSE) {
		logger.Info("----------------------------------------------")
		logger.Info(fmt.Sprintf("%v 连接正常关闭...", daddr))
	}

	if tc.nids_state == C.char(NIDS_RESET) {
		logger.Info("----------------------------------------------")
		logger.Info(fmt.Sprintf("%v 连接被RST关闭...", daddr))
	}

	if tc.nids_state == C.char(NIDS_DATA) {
		if tc.client.count_new > 0 {
			logger.Info(fmt.Sprintf("%v:%v <---- %v:%v", saddr, tc.addr.source, daddr, tc.addr.dest))
			logger.Info("浏览器接收数据")
			data := C.GoBytes(unsafe.Pointer(tc.client.data), C.int(tc.client.count_new))
			// logger.Info(fmt.Sprintf("%v", string(data)))
			ParseClientData(data)
		} else if tc.server.count_new > 0 {
			logger.Info(fmt.Sprintf("%v:%v ----> %v:%v", saddr, tc.addr.source, daddr, tc.addr.dest))
			logger.Info("服务器接收数据")
			data := C.GoBytes(unsafe.Pointer(tc.server.data), C.int(tc.server.count_new))
			// logger.Info(fmt.Sprintf("%v", string(data)))
			ParseServerData(data)
		}
	}
}
func RunNids(dev, filter string) {

	logger = log.NewLogger("http_capture.log", "debug")

	dev1 := C.CString(dev)
	defer C.free(unsafe.Pointer(dev1))

	filter1 := C.CString(filter)
	defer C.free(unsafe.Pointer(filter1))

	logger.Info("开始捕获http")
	logger.Info("使用网卡:" + dev + " 过滤规则:" + filter)
	C.start_nids(dev1, filter1)
}

func ParseClientData(data []byte) {
	if data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' {
		logger.Info("解析客户端数据")
		logger.Info("HTTP响应头：")
		logger.Info(string(data))
		dataStr := string(data)
		dataStrs := strings.Split(dataStr, "\r\n")
		for _, httpresdata := range dataStrs {
			if strings.Contains(httpresdata, "HTTP") {
				datas := strings.Split(httpresdata, " ")
				logger.Info(fmt.Sprintf("HTTP版本:%v 状态码: %v", datas[0], datas[1]))
				continue
			}

			httpresdatas := strings.Split(httpresdata, ": ")
			if strings.Contains(httpresdata, "Server") {
				logger.Info(fmt.Sprintf("服务器为（Server）:%v", httpresdatas[1]))
				continue
			}

			if strings.Contains(httpresdata, "Content-Type") {
				logger.Info(fmt.Sprintf("Content-Type:%v", httpresdatas[1]))
				continue
			}

			if strings.Contains(httpresdata, "Date") {
				logger.Info(fmt.Sprintf("当前时间为（Date）:%v", httpresdatas[1]))
				continue
			}

			if strings.Contains(httpresdata, "Cache-Control") {
				logger.Info(fmt.Sprintf("缓存机制为（Cache-Control）:%v", httpresdatas[1]))
				continue
			}

			if strings.Contains(httpresdata, "Expires") {
				logger.Info(fmt.Sprintf("资源期限为（Expires）:%v", httpresdatas[1]))
				continue
			}

			if strings.Contains(httpresdata, "Last-Modified") {
				logger.Info(fmt.Sprintf("最后一次修改的时间为（Last-Modified）:%v", httpresdatas[1]))
				continue
			}

			if strings.Contains(httpresdata, "ETag") {
				logger.Info(fmt.Sprintf("Etag为（ETag）:%v", httpresdatas[1]))
				continue
			}
			if httpresdata == "" {
				continue
			}
			logger.Info(httpresdata)
		}
	} else {
		logger.Info("实体内容为（续）：")
		logger.Info(string(data))
	}
}

func ParseServerData(data []byte) {
	logger.Info("解析服务器数据")
	logger.Info("HTTP请求头：")
	dataStr := string(data)
	dataStrs := strings.Split(dataStr, "\r\n")
	for _, httpreqdata := range dataStrs {
		if strings.Contains(httpreqdata, "GET") {
			logger.Info("HTTP请求方法为:GET")
		}
		if strings.Contains(httpreqdata, "POST") {
			logger.Info("HTTP请求方法为:POST")
		}
		if strings.Contains(httpreqdata, "HEAD") {
			logger.Info("HTTP请求方法为:HEAD")
		}
		if strings.Contains(httpreqdata, "PUT") {
			logger.Info("HTTP请求方法为:PUT")
		}
		if strings.Contains(httpreqdata, "DELETE") {
			logger.Info("HTTP请求方法为:DELETE")
		}
		if strings.Contains(httpreqdata, "PATCH") {
			logger.Info("HTTP请求方法为:PATCH")
		}
		if strings.Contains(httpreqdata, "OPTIONS") {
			logger.Info("HTTP请求方法为:OPTIONS")
		}
		if strings.Contains(httpreqdata, "CONNECT") {
			logger.Info("HTTP请求方法为:CONNECT")
		}
		if strings.Contains(httpreqdata, "TRACE") {
			logger.Info("HTTP请求方法为:TRACE")
		}
		if strings.Contains(httpreqdata, "HTTP") {
			datas := strings.Split(httpreqdata, " ")
			logger.Info(fmt.Sprintf("请求路径:%v", datas[1]))
			continue
		}
		if httpreqdata == "" {
			continue
		}
		logger.Info(httpreqdata)
	}
}
