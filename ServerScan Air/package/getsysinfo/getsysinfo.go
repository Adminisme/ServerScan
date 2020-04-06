package getsysinfo

import (
	"os"
	"os/user"
	"runtime"
)

type SystemInfo struct {
	OS 			  string
	ARCH          string
	HostName      string
	Groupid  	  string
	Userid		  string
	Username	  string
	UserHomeDir	  string
}

func GetSys() SystemInfo {
	var sysinfo SystemInfo

	sysinfo.OS = runtime.GOOS
	sysinfo.ARCH = runtime.GOARCH
	name, err := os.Hostname()
	if err == nil {
		sysinfo.HostName = name
	}

	u, err := user.Current()
	sysinfo.Groupid = u.Gid
	sysinfo.Userid = u.Uid
	sysinfo.Username = u.Username
	sysinfo.UserHomeDir = u.HomeDir

	return sysinfo
}