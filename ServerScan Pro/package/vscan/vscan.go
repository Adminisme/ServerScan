package vscan

import (
	"./proberbyte"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/axgle/mahonia"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type VScan struct {
	Exclude string

	Probes []Probe

	ProbesMapKName map[string]Probe
}

type Match struct {
	IsSoft bool

	Service     string
	Pattern     string
	VersionInfo string

	PatternCompiled *regexp.Regexp
}

type Probe struct {
	Name     string
	Data     string
	Protocol string

	Ports    string
	SSLPorts string

	TotalWaitMS  int
	TCPWrappedMS int
	Rarity       int
	Fallback     string

	Matchs *[]Match
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}

	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1: blankIndex+2]
	delimiter := data[blankIndex+2: blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive
}

func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]

	if !(proto == "TCP " || proto == "UDP ") {
		panic("Probe <protocol>must be either TCP or UDP.")
	}
	if len(other) == 0 {
		panic("nmap-service-probes - bad probe name")
	}

	directive := p.getDirectiveSyntax(other)

	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))
}

func (p *Probe) fromString(data string) error {
	var err error

	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	probeStr := lines[0]

	p.parseProbeInfo(probeStr)

	var matchs []Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "sslports ") {
			p.parseSSLPorts(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			p.parseTCPWrappedMS(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		}
	}
	p.Matchs = &matchs
	return err
}

func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

func (p *Probe) parseTotalWaitMS(data string) {
	p.TotalWaitMS, _ = strconv.Atoi(string(data[len("totalwaitms")+1:]))
}

func (p *Probe) parseTCPWrappedMS(data string) {
	p.TCPWrappedMS, _ = strconv.Atoi(string(data[len("tcpwrappedms")+1:]))
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(string(data[len("rarity")+1:]))
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

func (v *VScan) parseProbesFromContent(content string) {
	var probes []Probe

	var lines []string
	// 过滤掉规则文件中的注释和空行
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	if len(lines) == 0 {
		panic("Failed to read nmap-service-probes file for probe data, 0 lines read.")
	}
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}
		if c > 1 {
			panic("Only 1 Exclude directive is allowed in the nmap-service-probes file")
		}
	}
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		panic("Parse error on nmap-service-probes file: line was expected to begin with \"Probe \" or \"Exclude \"")
	}
	if c == 1 {
		v.Exclude = l[len("Exclude")+1:]
		lines = lines[1:]
	}
	content = strings.Join(lines, "\n")
	content = "\n" + content

	probeParts := strings.Split(content, "\nProbe")
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := Probe{}
		err := probe.fromString(probePart)
		if err != nil {
			continue
		}
		probes = append(probes, probe)
	}
	v.Probes = probes
}

func (v *VScan) parseProbesToMapKName(probes []Probe) {
	var probesMap = map[string]Probe{}
	for _, probe := range v.Probes {
		probesMap[probe.Name] = probe
	}
	v.ProbesMapKName = probesMap
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}

	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

type ProbesRarity []Probe

func (ps ProbesRarity) Len() int {
	return len(ps)
}

func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}

func sortProbesByRarity(probes []Probe) (probesSorted []Probe) {
	probesToSort := ProbesRarity(probes)
	sort.Stable(probesToSort)
	probesSorted = []Probe(probesToSort)
	return probesSorted
}

type Target struct {
	IP       string
	Port     int
	Protocol string
}

type Result struct {
	Target
	Service

	Error     string
}

type Service struct {
	Name        string
	Banner      string

	Extras
}

type Extras struct {
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
	Sign            string
	StatusCode      int
	ServiceURL      string
}

func (p *Probe) ContainsPort(testPort int) bool {
	ports := strings.Split(p.Ports, ",")

	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}

func (v *VScan) Explore(addr string) (Result, error) {
	var target Target
	target.IP = strings.Split(addr,":")[0]
	portstr, err := strconv.Atoi(strings.Split(addr,":")[1])
	if err == nil {
		target.Port = portstr
	}
	target.Protocol = "tcp"
	var probesUsed []Probe

	for _, probe := range v.Probes {
		if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
			probesUsed = append(probesUsed, probe)
		}
	}

	probesUsed = append(probesUsed, v.ProbesMapKName["NULL"])

	probesUsed = sortProbesByRarity(probesUsed)

	var probesUsedFiltered []Probe
	for _, probe := range probesUsed {
		probesUsedFiltered = append(probesUsedFiltered, probe)
	}
	probesUsed = probesUsedFiltered

	result, err := v.scanWithProbes(target, &probesUsed)

	return result, err
}

func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func (t *Target) GetAddress() string {
	return t.IP + ":" + strconv.Itoa(t.Port)
}

func trimBanner(buf []byte) string {
	bufStr := string(buf)
	if strings.Contains(bufStr, "SMB"){
		banner := hex.EncodeToString(buf)
		if (banner[0xa:0xa+6] == "534d42") {
			plain := banner[0xa2:]
			data,_ := hex.DecodeString(plain)
			var domain = ""
			var index = 0
			for _,s:=range data{
				index += 1
				if s != 0{
					domain = domain + string(s)
				}else {
					if data[index] == 0 && data[index+1] == 0{
						index += 1
						break
					}
				}
			}
			var hostname = ""
			var index2 = 0
			for _,h:=range data[index:]{
				index2 += 1
				if h !=0{
					hostname = hostname + string(h)
				}
				if data[index:][index2] == 0 && data[index:][index2+1] == 0{
					break
				}
			}
			smb_banner := "hostname: " + hostname + " domain: " + domain
			return smb_banner
		}
	}

	var src string
	for _,ch:=range bufStr{
		if (32 < int(ch)) && (int(ch)< 125) {
			src = src + string(ch)
		}else {
			src = src +" "
		}
	}

	re, _ := regexp.Compile("\\s{2,}")
	src = re.ReplaceAllString(src, ".")
	return strings.TrimSpace(src)
}

func trimHtml(src string) string {
	re, _ := regexp.Compile("\\<[\\S\\s]+?\\>")
	src = re.ReplaceAllStringFunc(src, strings.ToLower)
	re, _ = regexp.Compile("\\<style[\\S\\s]+?\\</style\\>")
	src = re.ReplaceAllString(src, "")
	re, _ = regexp.Compile("\\<script[\\S\\s]+?\\</script\\>")
	src = re.ReplaceAllString(src, "")
	re, _ = regexp.Compile("\\<[\\S\\s]+?\\>")
	src = re.ReplaceAllString(src, " ")
	re, _ = regexp.Compile("\\s{2,}")
	src = re.ReplaceAllString(src, " ")
	return strings.TrimSpace(src)
}

func ConvertToString(src string, srcCode string, tagCode string) string {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}

type HttpInfo struct{
	ServiceURL string
	StatusCode int
	ServerBanner string
	ServerSign string
}

func getHttpBanner(url string) (statsu bool,res HttpInfo) {
	var tag HttpInfo
	transport := &http.Transport {
		DialContext: (&net.Dialer{
			Timeout: time.Duration(2) * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config {
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout: 3* time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return false,tag
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false,tag
	}

	tag.ServerSign = resp.Header.Get("Server")
	tag.StatusCode = resp.StatusCode
	tag.ServiceURL = url

	if(strings.Contains(string(resp.Header.Get("Content-Type")), "2312")){
		tag.ServerBanner = trimHtml(ConvertToString(string(content), "gbk", "utf-8"))
	} else {
		tag.ServerBanner = trimHtml(string(content))
	}
	return true,tag
}

func (v *VScan) scanWithProbes(target Target, probes *[]Probe) (Result, error) {
	var result = Result{Target: target}

	for _, probe := range *probes {
		var response []byte

		probeData, _ := DecodeData(probe.Data)

		addr := target.GetAddress()

		response, _ = grabResponse(addr, probeData)

		if len(response) > 0 {
			found := false

			softFound := false
			var softMatch Match

			for _, match := range *probe.Matchs {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras := match.ParseVersionInfo(response)
					result.Service.Name = match.Service
					if(match.Service == "http") {
						if(target.Port == 443 || target.Port == 2443 || target.Port == 3443 || target.Port == 4443 || target.Port == 5443 || target.Port == 6443 || target.Port == 7443 || target.Port == 8443  || target.Port == 9443 || target.Port == 4430){
							url := "https://" + target.GetAddress()
							status,tag := getHttpBanner(url)
							if status{
								result.Banner = tag.ServerBanner
								result.Service.Extras = extras
								result.Service.Extras.Sign = tag.ServerSign
								result.Service.Extras.StatusCode = tag.StatusCode
								result.Service.Extras.ServiceURL =tag.ServiceURL
							}else {
								result.Service.Extras = extras
								result.Service.Extras.ServiceURL = url
							}
						}else{
							url := "http://" + target.GetAddress()
							status,tag := getHttpBanner(url)
							if status{
								result.Banner = tag.ServerBanner
								result.Service.Extras = extras
								result.Service.Extras.Sign = tag.ServerSign
								result.Service.Extras.StatusCode = tag.StatusCode
								result.Service.Extras.ServiceURL =tag.ServiceURL
							}else {
								result.Service.Extras = extras
								result.Service.Extras.ServiceURL = url
							}
						}
					} else if((match.Service == "ssl" || match.Service == "ssl/http"|| match.Service == "ssl-ms-rdp") && (target.Port == 443 || target.Port == 2443 || target.Port == 3443 || target.Port == 4443 || target.Port == 5443 || target.Port == 6443 || target.Port == 4430 || ( target.Port >= 80 && target.Port <= 99 ) || ( target.Port >= 7000 && target.Port <= 9999 ))){
						url := "https://" + target.GetAddress()
						status,tag := getHttpBanner(url)
						if status{
							result.Banner = tag.ServerBanner
							result.Service.Extras = extras
							result.Service.Extras.Sign = tag.ServerSign
							result.Service.Extras.StatusCode = tag.StatusCode
							result.Service.Extras.ServiceURL =tag.ServiceURL
						}else {
							result.Service.Extras = extras
							result.Service.Extras.ServiceURL = url
						}
					} else {
						result.Banner = trimBanner(response)
						result.Service.Extras = extras
					}
					found = true
					return result, nil
				} else
				if matched && match.IsSoft && !softFound {
					softFound = true
					softMatch = match
				}
			}

			fallback := probe.Fallback
			if _, ok := v.ProbesMapKName[fallback]; ok {
				fbProbe := v.ProbesMapKName[fallback]
				for _, match := range *fbProbe.Matchs {
					matched := match.MatchPattern(response)
					if matched && !match.IsSoft {
						extras := match.ParseVersionInfo(response)
						result.Service.Name = match.Service
						if(match.Service == "http") {
							if(target.Port == 443 || target.Port == 2443 || target.Port == 3443 || target.Port == 4443 || target.Port == 5443 || target.Port == 6443 || target.Port == 7443 || target.Port == 8443  || target.Port == 9443 || target.Port == 4430){
								url := "https://" + target.GetAddress()
								status,tag := getHttpBanner(url)
								result.Service.Extras.ServiceURL =tag.ServiceURL
								if status {
									result.Banner = tag.ServerBanner
									result.Service.Extras.Sign = tag.ServerSign
									result.Service.Extras.StatusCode = tag.StatusCode
								} else {
									result.Banner = trimBanner(response)
									result.Service.Extras = extras
								}
							}else{
								url := "http://" + target.GetAddress()
								status,tag := getHttpBanner(url)
								result.Service.Extras.ServiceURL =tag.ServiceURL
								if status{
									result.Banner = tag.ServerBanner
									result.Service.Extras.Sign = tag.ServerSign
									result.Service.Extras.StatusCode = tag.StatusCode
								} else {
									result.Banner = trimBanner(response)
									result.Service.Extras = extras
								}
							}
						}else {
							result.Banner = trimBanner(response)
							result.Service.Extras = extras
						}
						found = true
						return result, nil
					} else
					if matched && match.IsSoft && !softFound {
						softFound = true
						softMatch = match
					}
				}
			}
			if !found {
				if !softFound {

					result.Banner = trimBanner(response)

					if(strings.Contains(result.Banner, "HTTP/")) {
						result.Service.Name = "http"
					} else if (strings.Contains(result.Banner, "html")) {
						result.Service.Name = "http"
					} else {
						result.Service.Name = "unknown"
					}

					if(result.Service.Name == "http") {
						if(target.Port == 443 || target.Port == 2443 || target.Port == 3443 || target.Port == 4443 || target.Port == 5443 || target.Port == 6443 || target.Port == 7443 || target.Port == 8443  || target.Port == 9443 || target.Port == 4430){
							url := "https://" + target.GetAddress()
							status,tag := getHttpBanner(url)
							result.Service.Extras.ServiceURL =tag.ServiceURL
							if status{
								result.Banner = tag.ServerBanner
								result.Service.Extras.Sign = tag.ServerSign
								result.Service.Extras.StatusCode = tag.StatusCode
							}
						}else{
							url := "http://" + target.GetAddress()
							status,tag := getHttpBanner(url)
							result.Service.Extras.ServiceURL =tag.ServiceURL
							if status{
								result.Banner = tag.ServerBanner
								result.Service.Extras.Sign = tag.ServerSign
								result.Service.Extras.StatusCode = tag.StatusCode
							}
						}
					}

					return result, nil
				} else {

					result.Banner = trimBanner(response)

					extras := softMatch.ParseVersionInfo(response)
					result.Service.Extras = extras
					result.Service.Name = softMatch.Service

					return result, nil
				}
			}
		}
	}
	return result, nil
}

func grabResponse(addr string, data []byte) ([]byte, error) {
	var response []byte

	dialer := net.Dialer{}

	conn, errConn := dialer.Dial("tcp", addr)
	if errConn != nil {
		return response, errConn
	}
	defer conn.Close()

	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(time.Second*2))
		_, errWrite := conn.Write(data)
		if errWrite != nil {
			return response, errWrite
		}
	}

	conn.SetReadDeadline(time.Now().Add(time.Second*2))
	for true {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return response, errRead
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	return response, nil
}

func (v *VScan) Tagetsacn(addr []string, thread int) []string {
	var TagetBanners []string
	var info string
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}
	limiter := make(chan struct{}, thread)
	aliveHost := make(chan string, thread/2)
	go func() {
		for s := range aliveHost {
			fmt.Println(s)
		}
	}()
	for _,targetIP :=range addr{
		wg.Add(1)
		limiter <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			result, err := v.Explore(targetIP)
			mutex.Lock()
			if  err == nil{
				if (result.Service.Name == "http") {
					banner := result.Service.Banner
					if (len(banner) > 30) {
						banner = banner[:30] + "..."
					}
					info = banner
					if result.Service.Extras.Version != "" {
						info =  result.Service.Extras.Version + " - " + info
					}
					if result.Service.Extras.VendorProduct != "" {
						info =  result.Service.Extras.VendorProduct + " - " + info
					}
					if result.Service.Extras.Sign != "" {
						info =  result.Service.Extras.Sign + " - " + info
					}
				} else if (result.Service.Name == "ssl-ms-rdp"){
					info = result.Service.Name
				} else if (result.Service.Name == "microsoft-ds" && (strings.Contains(result.Service.Banner, "hostname") || strings.Contains(result.Service.Banner, "domain"))){
					info = result.Service.Extras.VendorProduct + " - " + result.Service.Name + " - " + result.Service.Banner
				} else {
					info = result.Service.Name
					if result.Service.Banner != "" &&  result.Service.Banner != "." && result.Service.Banner != ".@."{
						info = result.Service.Name + " - " + result.Service.Banner
					}
					if result.Service.Extras != (Extras{}) {
						if result.Service.Extras.Version != "" {
							info = info + " - " + result.Service.Extras.Version
						}
						if result.Service.Extras.VendorProduct != "" {
							info =  result.Service.Extras.VendorProduct + " - " + info
						}
						if result.Service.Extras.Sign != "" {
							info =  result.Service.Extras.Sign + " - " + info
						}
					}
				}
				if (info == ""){
					info = "unknown"
				}
				fmt.Printf("%s:%d (%s)\n",result.IP, result.Port, info)
				TagetBanner := targetIP + " (" + info + ")"
				TagetBanners = append(TagetBanners, TagetBanner)
				mutex.Unlock()
			}
			<-limiter
		}(targetIP)
	}
	wg.Wait()
	close(aliveHost)
	return TagetBanners
}

func (v *VScan) Init() {
	proberContent := bytes.NewReader(proberbyte.GetProber())
	proberReader, _ := gzip.NewReader(proberContent)
	proberStr, _ := ioutil.ReadAll(proberReader)
	v.parseProbesFromContent(string(proberStr))
	v.parseProbesToMapKName(v.Probes)
}

func GetProbes(aliveHosts []string) []string {
	v := VScan{}
	v.Init()
	//线程控制
	thread := 20
	if len(aliveHosts)>50 {
		thread = len(aliveHosts)/2
	}
	TagetBanners := v.Tagetsacn(aliveHosts,thread)
	return TagetBanners
}
