package main

import (
	"./package/icmpcheck"
	"./package/portscan"
	"./package/vscan"
	"flag"
	"fmt"
	"github.com/malfunkt/iprange"
	"os"
	"path/filepath"
	"regexp"
)

var version = "v1.0.2"
var printVersion bool

var hosts = ""
var ports = ""
var model = ""
var outFile = ""
var timeout int

func init()  {
	flag.BoolVar(&printVersion, "v", false, "ServerScan Build Version")

	flag.StringVar(&hosts, "h", "", "Host to be scanned, supports four formats:\n192.168.1.1\n192.168.1.1-10\n192.168.1.*\n192.168.1.0/24.")

	flag.StringVar(&ports, "p", "80-99,7000-9000,9001-9999,4430,1433,1521,3306,5000,5432,6379,21,22,100-500,873,4440,6082,3389,5560,5900-5909,1080,1900,10809,50030,50050,50070", "Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...")

	flag.StringVar(&model, "m", "icmp", "Scan Model icmp or tcp.")

	flag.IntVar(&timeout, "t", 2, "Setting scaner connection timeouts,Maxtime 30 Second.")

	flag.StringVar(&outFile, "o", "", "Output the scanning information to file.")

	flag.Parse()
}

func main(){
	if printVersion{
		fmt.Printf("ServerScan for Port Scaner and Service Version Detection.\nVersion:%s\nBy:Trim\n",version)
		os.Exit(0)
	}

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
		flag.Usage()
		return
	}

	portsPattern := `^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$|^\d+(-\d+)?(,\d+(-\d+)?)*$`
	portsRegexp := regexp.MustCompile(portsPattern)
	checkPort := portsRegexp.MatchString(ports)
	if ports != "" && checkPort == false{
		flag.Usage()
		return
	}

	if model != "tcp" && model != "icmp"{
		flag.Usage()
		return
	}

	if timeout <=0 || timeout >30 {
		flag.Usage()
		return
	}

	if outFile != "" && pathCheck(outFile) == false {
		fmt.Println("Outfile name exist or Outfile Path error.")
		return
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
		flag.Usage()
		return
	}

	var AliveHosts []string
	var AliveAddress []string
	var TagetBanners []string


	if model == "icmp"{
		AliveHosts = icmpcheck.ICMPRun(hostLists)
		for _,host :=range AliveHosts{
			fmt.Printf("(ICMP) Target '%s' is alive\n",host)
		}
		AliveHosts,AliveAddress = portscan.TCPportScan(AliveHosts,ports,model,timeout)
	}else if (model == "tcp"){
		AliveHosts,AliveAddress = portscan.TCPportScan(hostLists,ports,model,timeout)
		for _,host :=range AliveHosts{
			fmt.Printf("(TCP) Target '%s' is alive\n",host)
		}
		for _,addr :=range AliveAddress{
			fmt.Println(addr)
		}
	}else {
		flag.Usage()
		return
	}

	if len(AliveAddress) > 0 {
		TagetBanners = vscan.GetProbes(AliveAddress)
	}

	if outFile != "" && pathCheck(outFile) == true && len(AliveHosts) != 0 {
		f, _ := os.OpenFile(outFile, os.O_RDWR|os.O_CREATE, os.ModePerm)
		for _,host :=range AliveHosts{
			f.WriteString(host + "\n")
		}
		for _,addr :=range AliveAddress{
			f.WriteString(addr + "\n")
		}
		for _,taget :=range TagetBanners{
			f.WriteString(taget + "\n")
		}
		fmt.Printf("Output the scanning information in %s\n",outFile)
		defer f.Close()
	}

}

func pathCheck(files string) (bool)  {
	path, _ := filepath.Split(files)
	_, err := os.Stat(path)
	if err == nil {
		_, err2 := os.Stat(files)
		if err2 == nil {
			return false
		}
		if os.IsNotExist(err2) {
			return true
		}
	}else{
		err3 := os.MkdirAll(path, os.ModePerm)
		if err3 == nil {
			return true
		}else {
			return false
		}
	}
	return false
}

