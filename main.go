package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
)

var (
	optExtensions   []string
	optFileValidate bool
)

const (
	namespace = "ssl_expiration"
)

// SslCheck ...
type SslCheck struct {
	File    string   `json:"file"`
	Exclude []string `json:"exclude"`
	Address string   `json:"address"`
	Domain  string   `json:"domain"`
	Port    string   `json:"port"`
}

// SslExpirationExporter ...
type SslExpirationExporter struct {
	sslCheck     *SslCheck
	checkTimeout time.Duration
	mutex        sync.RWMutex

	secondsLeft   prometheus.Gauge
	daysLeft      prometheus.Gauge
	daysLeftRound prometheus.Gauge
	checkError    prometheus.Gauge
}

// constructor function
func (params *SslCheck) defaults() {
	if params.Domain == "" {
		params.Domain = params.Address
	}
	if params.Port == "" {
		if params.File == "" {
			params.Port = "443"
		}
	}
}

func (s *SslExpirationExporter) getStatus() ([]byte, error) {
	return []byte(""), nil
}

// CreateExporters ...
func CreateExporters(s SslCheck, checkTimeout time.Duration) (*SslExpirationExporter, error) {
	return &SslExpirationExporter{
		sslCheck:     &s,
		checkTimeout: checkTimeout,
		secondsLeft: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "seconds_left",
			Help:      "seconds left to expiration",
			ConstLabels: prometheus.Labels{
				"file":    fmt.Sprintf("%s", s.File),
				"address": fmt.Sprintf("%s", s.Address),
				"domain":  fmt.Sprintf("%s", s.Domain),
				"port":    fmt.Sprintf("%s", s.Port),
			},
		}),
		daysLeft: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "days_left",
			Help:      "days left to expiration",
			ConstLabels: prometheus.Labels{
				"file":    fmt.Sprintf("%s", s.File),
				"address": fmt.Sprintf("%s", s.Address),
				"domain":  fmt.Sprintf("%s", s.Domain),
				"port":    fmt.Sprintf("%s", s.Port),
			},
		}),
		daysLeftRound: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "days_left_round",
			Help:      "days left to expiration round",
			ConstLabels: prometheus.Labels{
				"file":    fmt.Sprintf("%s", s.File),
				"address": fmt.Sprintf("%s", s.Address),
				"domain":  fmt.Sprintf("%s", s.Domain),
				"port":    fmt.Sprintf("%s", s.Port),
			},
		}),
		checkError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "check_error",
			Help:      "check error",
			ConstLabels: prometheus.Labels{
				"file":    fmt.Sprintf("%s", s.File),
				"address": fmt.Sprintf("%s", s.Address),
				"domain":  fmt.Sprintf("%s", s.Domain),
				"port":    fmt.Sprintf("%s", s.Port),
			},
		}),
	}, nil
}

// Describe ...
func (s *SslExpirationExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.secondsLeft.Desc()
	ch <- s.daysLeft.Desc()
	ch <- s.daysLeftRound.Desc()
	ch <- s.checkError.Desc()
}

func doCheck(s *SslCheck, checkTimeout time.Duration) (time.Duration, error) {
	log.Printf("debug: {address: %s, domain: %s, port: %s, file: %s}", s.Address, s.Domain, s.Port, s.File)
	NotAfter := time.Duration(0)
	if s.File != "" {
		cert, err := loadCert(s.File)
		if err != nil {
			return time.Duration(0), err
		}
		NotAfter = cert.NotAfter.Sub(time.Now())
	} else {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", s.Address, s.Port), checkTimeout)
		if err != nil {
			return time.Duration(0), err
		}
		defer func(conn net.Conn) {
			err := conn.Close()
			if err != nil {
				log.Printf("%s", err)
			}
		}(conn)
		config := &tls.Config{
			ServerName:         s.Domain,
			InsecureSkipVerify: true,
		}
		c := tls.Client(conn, config)
		err = c.Handshake()
		if err != nil {
			return time.Duration(0), err
		}
		NotAfter = c.ConnectionState().PeerCertificates[0].NotAfter.Sub(time.Now())
	}
	return NotAfter, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("Could not decode")
	}
	log.Printf("debug: type IN: %s}", block.Type)
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("Not CERTIFICATE file  %s", path)
	}
	log.Printf("debug: type OUT: %s}", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func getCertificates(root string, exclude []string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && inArray(path, exclude) {
			return filepath.SkipDir
		}

		if info.IsDir() {
			return nil
		}

		if !inArray(path, exclude) {
			if inArray(filepath.Ext(path), optExtensions) {
				matches = append(matches, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return matches, nil
}

// Collect ...
func (s *SslExpirationExporter) Collect(ch chan<- prometheus.Metric) {
	s.mutex.Lock()
	defer func() {
		ch <- s.secondsLeft
		ch <- s.daysLeft
		ch <- s.daysLeftRound
		ch <- s.checkError
		s.mutex.Unlock()
	}()

	res, err := doCheck(s.sslCheck, s.checkTimeout)
	if err != nil {
		fmt.Printf("%s\n", err)
		s.checkError.Set(float64(1))
		return
	}

	s.secondsLeft.Set(res.Seconds())
	s.daysLeft.Set(res.Hours() / 24)
	round := math.Floor(res.Hours() / 24)
	if time.Now().Hour() < 12 {
		round++
	}
	s.daysLeftRound.Set(round)
	s.checkError.Set(float64(0))
}

func inArray(val interface{}, array interface{}) (result bool) {
	values := reflect.ValueOf(array)
	if reflect.TypeOf(array).Kind() == reflect.Slice || values.Len() > 0 {
		for i := 0; i < values.Len(); i++ {
			if reflect.DeepEqual(val, values.Index(i).Interface()) {
				return true
			}
		}
	}
	return false
}

func main() {
	var listen string
	listenDef := "0.0.0.0:9443"
	pflag.StringVar(
		&listen,
		"listen",
		listenDef,
		"Listen address. Env LISTEN also can be used.",
	)

	var checklistFile string
	checklistFileDef := "/etc/prometheus/prometheus-ssl-expiration-exporter.yaml"
	pflag.StringVar(
		&checklistFile,
		"checklist-file",
		checklistFileDef,
		"Checklist file",
	)

	var metricsPath string
	metricsPathDef := "/metrics"
	pflag.StringVar(
		&metricsPath,
		"metrics-path",
		metricsPathDef,
		"Metrics path",
	)

	var checkTimeout time.Duration
	checkTimeoutDef := 5 * time.Second
	pflag.DurationVar(
		&checkTimeout,
		"check_timeout",
		checkTimeoutDef,
		"Check timeout",
	)

	var extensionsString string
	extensionsStringDef := "crt,pem"
	pflag.StringVar(
		&extensionsString,
		"file-extensions",
		extensionsStringDef,
		"Certificate files extensions",
	)

	var fileValidate bool
	fileValidateDef := true
	pflag.BoolVar(
		&fileValidate,
		"file-validate",
		fileValidateDef,
		"Validate for valid certs (do not monitor non CERTIFICATE {file-extensions} files)",
	)

	pflag.Parse()

	if listen == listenDef && len(os.Getenv("LISTEN")) > 0 {
		listen = os.Getenv("LISTEN")
	}
	if checklistFile == checklistFileDef && len(os.Getenv("CHECKLIST_FILE")) > 0 {
		checklistFile = os.Getenv("CHECKLIST_FILE")
	}
	if metricsPath == metricsPathDef && len(os.Getenv("METRICS_PATH")) > 0 {
		metricsPath = os.Getenv("METRICS_PATH")
	}
	if checkTimeout == checkTimeoutDef && len(os.Getenv("CHECK_TIMEOUT")) > 0 {
		var err error
		checkTimeout, err = time.ParseDuration(os.Getenv("CHECK_TIMEOUT"))
		if err != nil {
			panic(err)
		}
	}
	if extensionsString == extensionsStringDef && len(os.Getenv("FILE_EXTENSIONS")) > 0 {
		extensionsString = os.Getenv("FILE_EXTENSIONS")
	}

	if fileValidate == fileValidateDef && len(os.Getenv("FILE_VALIDATE")) > 0 {
		boolVal, err := strconv.ParseBool(os.Getenv("FILE_VALIDATE"))
		if err != nil {
			optFileValidate = fileValidateDef
		}
		optFileValidate = boolVal
	}

	for _, ext := range strings.Split(extensionsString, ",") {
		optExtensions = append(optExtensions, "."+ext)
	}

	var checklist = make([]SslCheck, 256)
	config, err := ioutil.ReadFile(checklistFile)
	if err != nil {
		log.Fatal("Couldn't read config: ", err)
	}
	err = yaml.Unmarshal(config, &checklist)
	if err != nil {
		log.Fatal("Couldn't parse config: ", err)
	}

	var checklistStrings []string
	var checklistParsed []SslCheck

	for check := range checklist {
		t := checklist[check]
		if t.Address == "" && t.Domain == "" && t.File == "" {
			log.Printf("Error: Config error, address/domain/file is required for target: {address: %s, domain: %s, port: %s, file: %s}", t.Address, t.Domain, t.Port, t.File)
			continue
		}
		t.defaults()

		var ts string
		if t.File == "" {
			ts = strings.Join([]string{t.Address, t.Domain, t.Port}, ":")
			if inArray(ts, checklistStrings) {
				log.Printf("Warn: duplicate address/domain/port target: {address: %s, domain: %s, port: %s}", t.Address, t.Domain, t.Port)
				continue
			}
			checklistStrings = append(checklistStrings, ts)
			checklistParsed = append(checklistParsed, t)
		} else {
			var files []string

			fi, err := os.Stat(t.File)
			if err != nil {
				log.Print(err)
				continue
			}

			// if target is directory, load certificates with file-validete option
			// if target is file -add to checks, ignore file-validate option
			if !fi.IsDir() {
				var tf = SslCheck{File: t.File}
				checklistStrings = append(checklistStrings, t.File)
				checklistParsed = append(checklistParsed, tf)
			} else {
				files, err = getCertificates(t.File, t.Exclude)
				if err != nil {
					log.Printf("Err: Invalid target in config file: %s\nerr: %s", t.File, err)
					continue
				}

				for _, file := range files {
					if inArray(file, checklistStrings) {
						continue
					}
					_, err := loadCert(file)
					if optFileValidate == false {
						if err != nil {
							continue
						}
					}
					var tf = SslCheck{File: file}
					checklistStrings = append(checklistStrings, file)
					checklistParsed = append(checklistParsed, tf)
				}
			}
		}
	}

	checklistStrings = nil

	for _, check := range checklistParsed {
		exporter, err := CreateExporters(check, checkTimeout)
		if err != nil {
			log.Fatal(err)
		}
		prometheus.MustRegister(exporter)
	}

	log.Printf("Statring ssl expiration exporter.")

	http.Handle(metricsPath, promhttp.Handler())
	err = http.ListenAndServe(listen, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
