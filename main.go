package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/valyala/fastjson"
)

// test Go specific regex patterns: https://regoio.herokuapp.com
var (
	cn = flag.String(
		"commonName",
		`((?:(?:[a-z0-9]\.|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])\.)+mil)`, // match dotmil by default
		"common name regex search pattern",
	)
	outputJSON = flag.Bool("json", false, "output as json")
)

func main() {
	flag.Parse()

	done := make(chan interface{})
	defer close(done)

	jsonStr := make(chan string)
	go reader(jsonStr, done)

	parsed := make(chan Result)
	go parser(done, jsonStr, parsed)

	if *outputJSON {
		enc := json.NewEncoder(os.Stdout)
		for res := range parsed {
			if err := enc.Encode(res); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		seen := make(map[string]bool)
		w := csv.NewWriter(os.Stdout)
		for res := range parsed {
			for _, s := range res.Subdomains {
				if found := seen[s]; !found {
					o := []string{res.IP, s}
					w.Write(o)
				}
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			log.Fatal(err)
		}
	}
}

type Result struct {
	IP         string   `json:"ip"`
	Subdomains []string `json:"subdomains"`
}

func reader(c chan<- string, done <-chan interface{}) {
	defer close(c)
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		select {
		case <-done:
			return
		case c <- sc.Text():
		}
	}
}

func parser(done <-chan interface{}, i <-chan string, c chan<- Result) {
	defer close(c)

	var p fastjson.Parser

	cnPat := fmt.Sprintf("(?i)%s\\b", *cn) // subjectCN can only precede whitespace or end of line
	altNamePat := fmt.Sprintf("(?i)%s", *cn)
	cnRx := regexp.MustCompile(cnPat)
	altNameRx := regexp.MustCompile(altNamePat)

	for str := range i {
		str = fixEscape(str) // attempt repair before parse

		j, err := p.Parse(str)
		// skip line output if invalid JSON throws error
		if err != nil {
			continue
		}

		ip := string(j.GetStringBytes("ip"))

		subdomains := []string{cleanVal(j.GetStringBytes("certificateChain", "0", "subjectCN"))}
		if ok := cnRx.MatchString(subdomains[0]); !ok {
			continue
		}

		subdomains = append(subdomains, altNameRx.FindAllString(cleanVal(j.GetStringBytes("certificateChain", "0", "subjectAltName")), -1)...)

		res := Result{IP: ip, Subdomains: subdomains}

		select {
		case <-done:
			return
		case c <- res:
		}

	}

}

var (
	invalidEscapePat = regexp.MustCompile(`\\(?:[0-7]{3}|\*)`)
)

func fixEscape(src string) string {
	return invalidEscapePat.ReplaceAllString(src, " ")
}

func cleanVal(b []byte) string {
	s := strings.ToLower(string(b))
	return s
}
