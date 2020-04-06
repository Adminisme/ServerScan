package main

import (
	"./package/icmpcheck"
	"./package/portscan"
	"./package/vscan"
	"fmt"
	"github.com/malfunkt/iprange"
	"os"
	"regexp"
)

func main(){
	var argv []string

	if (len(os.Args) != 4) {
		fmt.Println("ServerScan for Port Scaner and Service Version Detection.\nVersion: v1.0.2\nBy: Trim\n" +
			"HOST  Host to be scanned, supports four formats:\n\t\t192.168.1.1\n\t\t192.168.1.1-10\n\t\t192.168.1.*\n\t\t192.168.1.0/24\n"+
			"PORT  Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...\n"+
			"MODEL Scan Model: icmp or tcp")
		os.Exit(0)
	}

	for _, s := range os.Args {
		argv = append(argv,s)
	}

	hosts := argv[1]

	hostsPattern := `^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\/(\d{1}|[0-2]{1}\d{1}|3[0-2])$|^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$`
	hostsRegexp := regexp.MustCompile(hostsPattern)
	checkHost := hostsRegexp.MatchString(hosts)

	hostsPattern2 := `\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})\-((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2}))\b`
	hostsRegexp2 := regexp.MustCompile(hostsPattern2)
	checkHost2 := hostsRegexp2.MatchString(hosts)

	hostsPattern3 := `((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(\*$)`
	hostsRegexp3 := regexp.MustCompile(hostsPattern3)
	checkHost3 := hostsRegexp3.MatchString(hosts)

	if hosts == "" || (checkHost == false && checkHost2 == false && checkHost3 == false){
		fmt.Println("HOST  Host to be scanned, supports four formats:\n\t\t192.168.1.1\n\t\t192.168.1.1-10\n\t\t192.168.1.*\n\t\t192.168.1.0/24\n")
		os.Exit(0)
	}

	var hostLists []string
	hostlist, err := iprange.ParseList(hosts)
	if err == nil {
		hostsList := hostlist.Expand()
		for _, host := range hostsList {
			host :=host.String()
			hostLists = append(hostLists, host)
		}
	}else {
		fmt.Println("HOST  Host to be scanned, supports four formats:\n\t\t192.168.1.1\n\t\t192.168.1.1-10\n\t\t192.168.1.*\n\t\t192.168.1.0/24\n")
		os.Exit(0)
	}


	ports := argv[2]
	portsPattern := `^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$|^\d+(-\d+)?(,\d+(-\d+)?)*$`
	portsRegexp := regexp.MustCompile(portsPattern)
	checkPort := portsRegexp.MatchString(ports)
	if ports != "" && checkPort == false{
		fmt.Println("PORT Error.  Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...\n")
		os.Exit(0)
	}

	model := argv[3]

	var AliveHosts []string
	var AliveAddress []string

	if model == "icmp"{
		AliveHosts = icmpcheck.ICMPRun(hostLists)
		for _,host :=range AliveHosts{
			fmt.Printf("(ICMP) Target '%s' is alive\n",host)
		}
		_,AliveAddress = portscan.TCPportScan(AliveHosts,ports,model)
	}else if (model == "tcp"){
		AliveHosts,AliveAddress = portscan.TCPportScan(hostLists,ports,model)
		for _,host :=range AliveHosts{
			fmt.Printf("(TCP) Target '%s' is alive\n",host)
		}
		for _,addr :=range AliveAddress{
			fmt.Println(addr)
		}
	}else {
		fmt.Println("MODEL Error. Scan Model: icmp or tcp")
		os.Exit(0)
	}

	if len(AliveAddress) > 0 {
		vscan.GetProbes(AliveAddress)
	}

}
