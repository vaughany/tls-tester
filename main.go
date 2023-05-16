package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var urls = []string{
	"apple.com",
	"facebook.com",
	"google.com",
	"twitter.com",
}

type Result int

type URLTestResult struct {
	tls10, tls11, tls12, tls13                 Result
	tls10note, tls11note, tls12note, tls13note string
}

const (
	resultUnknown Result = iota
	resultSupportedOkay
	resultSupportedNotOkay
	resultUnsupportedOkay
	resultUnsupportedNotOkay
)

var (
	versionsStrings = map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	resultsStrings = map[Result]string{
		resultUnknown:            `Unknown result`,
		resultSupportedOkay:      `Supported (good)`,
		resultSupportedNotOkay:   `Supported (bad)`,
		resultUnsupportedOkay:    `Unsupported (good)`,
		resultUnsupportedNotOkay: `Unsupported (okay)`,
	}

	resultsShortStrings = map[Result]string{
		resultUnknown:            `unknown`,
		resultSupportedOkay:      `okay`,
		resultSupportedNotOkay:   `not okay`,
		resultUnsupportedOkay:    `okay`,
		resultUnsupportedNotOkay: `not okay`,
	}

	resultsIcons = map[Result]string{
		resultUnknown:            `❓`,
		resultSupportedOkay:      `✅`,
		resultSupportedNotOkay:   `❌`,
		resultUnsupportedOkay:    `✅`,
		resultUnsupportedNotOkay: `❌`,
	}

	// Where we'll store all the results of the tests until we're ready to display it or write it out.
	TestResults      = make(map[string]URLTestResult)
	TestResultsMutex = sync.RWMutex{}

	jar *cookiejar.Jar
	fh  *os.File
	err error

	plural  string
	numJobs int
)

const (
	testConnectionReset           = `connection reset by peer`
	testConnectionRefused         = `connection refused`
	testContextDeadlineExceeded   = `context deadline exceeded`
	testFailedToVerifyCertificate = `failed to verify certificate`
	testHandshakeFailure          = `handshake failure`
	testNoSuchHost                = `no such host`
	testNoRouteToHost             = `no route to host`
	testProtocolNotSupported      = `protocol version not supported`
	testTimeoutExceeded           = `Timeout exceeded while awaiting headers`
	testUnsupportedProtocol       = `server selected unsupported protocol`
	testNotATLSHandshake          = `first record does not look like a TLS handshake`
	testHTTPResponse              = `server gave HTTP response to HTTPS client`

	workers = 10
)

func main() {
	fmt.Println("TLS Tester v0.3")

	// Flags.
	url := flag.String(`url`, ``, `URL to test (e.g. 'google.com')`)
	flag.Parse()
	if len(*url) > 0 {
		urls = []string{*url}
	}

	// Put the number of URLs to be tested into a variable as we use it in several places for output and channel size.
	numJobs = len(urls)

	// What we're doing, and pluralising the output if needs be (I *hate* e.g. '1 URLs').
	if numJobs > 1 {
		plural = `s`
	}
	fmt.Printf("Checking %d URL%s for TLS security\n", numJobs, plural)

	startupTime := time.Now()

	// Open a file for writing now and quit early if it fails.
	fh, err = os.Create(`./output.csv`)
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	// Set up a new cookie jar (some websites fail if a cookie cannot be written and then read back).
	jar, err = cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	// Set up the jobs and results channels.
	jobs := make(chan string, numJobs)
	results := make(chan string, numJobs)

	// Spin up some workers.
	for w := 1; w <= workers; w++ {
		go processURL(w, jobs, results)
	}

	// Send the jobs.
	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	// Receive the results.
	for a := 1; a <= numJobs; a++ {
		<-results
	}

	fmt.Printf("Processing complete.\n\n")

	// Write out the data to screen, CSV, wherever.
	var wg sync.WaitGroup

	wg.Add(2)
	writeScreen(TestResults, &wg)
	writeCSV(TestResults, &wg)
	wg.Wait()

	fmt.Printf("Done. Tested %d URL%s in %s.\n", numJobs, plural, time.Since(startupTime).Round(time.Millisecond))
}

func processURL(id int, jobs <-chan string, results chan<- string) {
	for url := range jobs {
		fmt.Printf("    Processing %s...\n", url)

		// Set up a waitgroup for the four TLS version tests.
		var wg sync.WaitGroup

		// Set defaults for the output.
		testResult := URLTestResult{resultUnknown, resultUnknown, resultUnknown, resultUnknown, ``, ``, ``, ``}

		for _, tlsVersion := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
			wg.Add(1)
			go testTLSVersion(tlsVersion, url, &testResult, &wg)
		}

		// Wait for all the tests to complete.
		wg.Wait()

		TestResultsMutex.Lock()
		TestResults[url] = testResult
		TestResultsMutex.Unlock()

		results <- url
	}
}

func testTLSVersion(tlsVersion uint16, url string, testResult *URLTestResult, wg *sync.WaitGroup) {
	defer wg.Done()

	var (
		tlsURLResult = resultUnknown // Defaults to 'unknown'.
		tlsURLNote   = ""            // Optional text about the test (e.g. the error encountered).
	)

	client := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tlsVersion,
				MaxVersion: tlsVersion,
			},
		},
	}

	request, err := http.NewRequest("GET", `https://`+url, nil)
	if err != nil {
		panic(err)
	}

	_, err = client.Do(request)
	switch {
	case err != nil && strings.Contains(err.Error(), testConnectionReset):
		tlsURLNote = testConnectionReset

		if tlsVersion == tls.VersionTLS10 || tlsVersion == tls.VersionTLS11 {
			tlsURLResult = resultUnsupportedOkay
		} else {
			tlsURLResult = resultSupportedNotOkay
		}

	case err != nil && strings.Contains(err.Error(), testUnsupportedProtocol):
		tlsURLNote = testUnsupportedProtocol

		if tlsVersion == tls.VersionTLS10 || tlsVersion == tls.VersionTLS11 {
			tlsURLResult = resultUnsupportedOkay
		} else {
			tlsURLResult = resultSupportedNotOkay
		}

	case err != nil && strings.Contains(err.Error(), testProtocolNotSupported):
		tlsURLNote = testProtocolNotSupported

		if tlsVersion == tls.VersionTLS10 || tlsVersion == tls.VersionTLS11 {
			tlsURLResult = resultUnsupportedOkay
		} else {
			tlsURLResult = resultSupportedNotOkay
		}

	case err != nil && strings.Contains(err.Error(), testContextDeadlineExceeded):
		tlsURLNote = testContextDeadlineExceeded

	case err != nil && strings.Contains(err.Error(), testNoSuchHost):
		tlsURLNote = testNoSuchHost

	case err != nil && strings.Contains(err.Error(), testFailedToVerifyCertificate):
		tlsURLNote = testFailedToVerifyCertificate

	case err != nil && strings.Contains(err.Error(), testTimeoutExceeded):
		tlsURLNote = testTimeoutExceeded

	case err != nil && strings.Contains(err.Error(), testConnectionRefused):
		tlsURLNote = testConnectionRefused

	case err != nil && strings.Contains(err.Error(), testHandshakeFailure):
		tlsURLNote = testHandshakeFailure

	case err != nil && strings.Contains(err.Error(), testNoRouteToHost):
		tlsURLNote = testNoRouteToHost

	case err != nil && strings.Contains(err.Error(), testNotATLSHandshake):
		tlsURLNote = testNotATLSHandshake

	case err != nil && strings.Contains(err.Error(), testHTTPResponse):
		tlsURLNote = testHTTPResponse

	case err != nil:
		// This catches any errors not already handled.
		fmt.Print(err.Error())

		tlsURLNote = err.Error()

	case err == nil:
		if tlsVersion == tls.VersionTLS10 || tlsVersion == tls.VersionTLS11 {
			tlsURLResult = resultSupportedNotOkay
		} else {
			tlsURLResult = resultUnsupportedOkay
		}

	default:
		panic(`something went wrong`)
	}

	switch tlsVersion {
	case tls.VersionTLS10:
		testResult.tls10 = tlsURLResult
		testResult.tls10note = tlsURLNote
	case tls.VersionTLS11:
		testResult.tls11 = tlsURLResult
		testResult.tls11note = tlsURLNote
	case tls.VersionTLS12:
		testResult.tls12 = tlsURLResult
		testResult.tls12note = tlsURLNote
	case tls.VersionTLS13:
		testResult.tls13 = tlsURLResult
		testResult.tls13note = tlsURLNote
	}
}

// Basic 'tick', 'cross' or 'unknown' output for the screen.
func writeScreen(results map[string]URLTestResult, wg *sync.WaitGroup) {
	defer wg.Done()

	// Sort the data via the keys.
	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for i, key := range keys {
		fmt.Printf("% 5d: %50s:\t\t%s %s %s %s\n", i+1, key, resultsIcons[results[key].tls10], resultsIcons[results[key].tls11], resultsIcons[results[key].tls12], resultsIcons[results[key].tls13])
	}
}

func writeCSV(results map[string]URLTestResult, wg *sync.WaitGroup) {
	defer wg.Done()

	// Writing the 'header' of the CSV file.
	csvLine := fmt.Sprintf("URL,%s,%s,%s,%s,%s note,%s note,%s note,%s note\n",
		versionsStrings[tls.VersionTLS10], versionsStrings[tls.VersionTLS11], versionsStrings[tls.VersionTLS12], versionsStrings[tls.VersionTLS13],
		versionsStrings[tls.VersionTLS10], versionsStrings[tls.VersionTLS11], versionsStrings[tls.VersionTLS12], versionsStrings[tls.VersionTLS13],
	)
	_, err := fh.WriteString(csvLine)
	if err != nil {
		panic(err)
	}

	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Create one line of the CSV file from the results and notes of this URL's test.
	for _, key := range keys {
		// fmt.Printf("% 5d: %50s:\t\t%s %s %s %s\n", i+1, key, resultsIcons[results[key].tls10], resultsIcons[results[key].tls11], resultsIcons[results[key].tls12], resultsIcons[results[key].tls13])

		csvLine = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			key,
			resultsShortStrings[results[key].tls10],
			resultsShortStrings[results[key].tls11],
			resultsShortStrings[results[key].tls12],
			resultsShortStrings[results[key].tls13],
			results[key].tls10note,
			results[key].tls11note,
			results[key].tls12note,
			results[key].tls13note,
		)

		// Write this URL's tests out to the CSV file.
		_, err = fh.WriteString(csvLine)
		if err != nil {
			panic(err)
		}
	}
}
