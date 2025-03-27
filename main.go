package main

import (
	"flag"
	"fmt"
	"github/EnderCHX/websafe-go/ethernet"
	"github/EnderCHX/websafe-go/filter"
	"github/EnderCHX/websafe-go/http"
	"github/EnderCHX/websafe-go/security"
	"os"
	"os/exec"
)

func PrintUseage() {
	cmd := exec.Command(os.Args[0], "-h")
	out, _ := cmd.CombinedOutput()
	fmt.Println(string(out))
}

func init() {
	flag.StringVar(&device, "d", "eth0", "设备名称")
	flag.StringVar(&bpf, "f", "", "BPF过滤规则")
	flag.IntVar(&mode, "m", 1, "运行模式：1. http 2. ethernet 3. 扫描攻击检测")
}

var device string
var bpf string
var mode int

func main() {
	flag.Parse()
	if len(os.Args) <= 1 {
		PrintUseage()
		return
	}

	if bpf == "n1" || bpf == "n2" || bpf == "n3" || bpf == "n4" {
		bpf = filter.FilterMap[bpf]
	}

	switch mode {
	case 1:
		go http.RunNids(device, bpf)
	case 2:
		go ethernet.RunEthernet(device, bpf)
	case 3:
		go security.Run(device)
	default:
		PrintUseage()
	}

	select {}
}
