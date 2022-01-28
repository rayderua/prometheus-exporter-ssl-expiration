package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
    "strings"
    "reflect"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	yaml "gopkg.in/yaml.v2"
)

var extensions []string
const (
	namespace = "ssl_expiration"
)

// SslCheck ...
type SslCheck struct {
    File string `json:"file"`
	Address string `json:"address"`
	Domain string `json:"domain"`
	Port    string `json:"port"`
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
func(params *SslCheck) defaults(){
    if params.Domain == "" {
        params.Domain = params.Address
    }
    if params.Port == "" {
        params.Port = "443"
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
			Namespace:   namespace,
			Name:        "seconds_left",
			Help:        "seconds left to expiration",
			ConstLabels: prometheus.Labels{
			    "instance": fmt.Sprintf("%s:%s", s.Address, s.Port),
			    "domain": fmt.Sprintf("%s", s.Domain),
			    "address": fmt.Sprintf("%s", s.Address),
			    "file": fmt.Sprintf("%s", s.File),
			},
		}),
		daysLeft: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "days_left",
			Help:        "days left to expiration",
			ConstLabels: prometheus.Labels{
			    "instance": fmt.Sprintf("%s:%s", s.Address, s.Port),
			    "domain": fmt.Sprintf("%s", s.Domain),
			    "address": fmt.Sprintf("%s", s.Address),
			    "file": fmt.Sprintf("%s", s.File),
            },
		}),
		daysLeftRound: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "days_left_round",
			Help:        "days left to expiration round",
			ConstLabels: prometheus.Labels{
			    "instance": fmt.Sprintf("%s:%s", s.Address, s.Port),
			    "domain": fmt.Sprintf("%s", s.Domain),
			    "address": fmt.Sprintf("%s", s.Address),
			    "file": fmt.Sprintf("%s", s.File),
            },
		}),
		checkError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "check_error",
			Help:        "check error",
			ConstLabels: prometheus.Labels{
			    "instance": fmt.Sprintf("%s:%s", s.Address, s.Port),
			    "domain": fmt.Sprintf("%s", s.Domain),
			    "address": fmt.Sprintf("%s", s.Address),
			    "file": fmt.Sprintf("%s", s.File),
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

    NotAfter := time.Duration(0)
    if ( s.File != "" ) {
        raw, err := ioutil.ReadFile(s.File)
        if err != nil {
            return time.Duration(0), err
        }
        block, _ := pem.Decode([]byte(raw))
        if block == nil {
            return time.Duration(0), err
        }

        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            return time.Duration(0), err
        }

        NotAfter = cert.NotAfter.Sub(time.Now())
    } else {
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", s.Address, s.Port), checkTimeout)
        if err != nil {
            return time.Duration(0), err
        }
        defer conn.Close()
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

func getCertificates(root string) ([]string, error) {
    var matches []string

    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if info.IsDir() {
            return nil
        }

        for _, ext := range extensions {
            if ( ext == filepath.Ext(path) ) {
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
    round := math.Floor((res.Hours() / 24))
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
	checkTimeoutDef := time.Duration(5 * time.Second)
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
		"extensions",
		extensionsStringDef,
		"Certificate files extensions",
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

    for _, ext := range strings.Split(extensionsString,",")  {
        extensions = append(extensions, "." + ext)
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
	    if ( t.Address == "" && t.Domain == "" && t.File == "" ) {
            log.Printf("Error: Config error, address/domain/file is required for target: {address: %s, domain: %s, port: %s, file: %s}", t.Address, t.Domain, t.Port, t.File)
	        continue
        }
        t.defaults()

        var ts string
	    if ( t.File == "" ) {
            ts = strings.Join([]string {t.Address,t.Domain,t.Port},":")
            if ( inArray(ts, checklistStrings) ) {
                log.Printf("Warn: duplicate address/domain/port target: {address: %s, domain: %s, port: %s}", t.Address, t.Domain, t.Port)
                continue
            }
            checklistStrings = append(checklistStrings, ts)
            checklistParsed = append(checklistParsed, t)
	    } else {
            files, err := getCertificates(t.File)
            if err != nil {
                log.Fatalf("Err: Invalid target in config file: %s\nerr: %s", t.File, err)
                continue
            }

            for _, file := range files {
                if ( inArray(file, checklistStrings) ) {
                    log.Printf("Warn: duplicate file target: %s", t.File)
                    continue
                }
	            var tf = SslCheck{File: file}
                checklistStrings = append(checklistStrings, file)
                // TODO: check if defaults is needed
                tf.defaults()
                checklistParsed = append(checklistParsed, tf)
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
