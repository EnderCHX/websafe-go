package main

import (
	"github/EnderCHX/websafe-go/ethernet"
	"github/EnderCHX/websafe-go/filter"
	"github/EnderCHX/websafe-go/log"
	"sync"
)

func main() {
	log.Setup("log.log", "debug")
	logger := log.GetLogger()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	logger.Info("Start NIDS")
	// go http.RunNids("enp2s0", filter.HTTPNot443)
	go ethernet.RunEthernet("enp2s0", filter.HTTPNot443)
	logger.Info("Start Ethernet")
	wg.Wait()
}
