package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

var urls = []string{
	"apple.com",
	"facebook.com",
	"google.com",
	"twitter.com",
}

type Result int

type TLSResult struct {
	tls10, tls11, tls12, tls13                 Result
	tls10note, tls11note, tls12note, tls13note string
}

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

	resultUnknown Result = iota
	resultSupportedOkay
	resultSupportedNotOkay
	resultUnsupportedOkay
	resultUnsupportedNotOkay
)

func main() {
	fmt.Println("TLS Tester v0.1")

	url := flag.String(`url`, ``, `URL to test (e.g. 'google.com')`)
	flag.Parse()
	if len(*url) > 0 {
		urls = []string{*url}
	}

	fmt.Printf("Checking %d URLs for TLS security\n", len(urls))

	startupTime := time.Now()

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	fh, err := os.Create(`./output.csv`)
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	csvLine := fmt.Sprintf("URL,%s,%s,%s,%s,%s note,%s note,%s note,%s note\n",
		versionsStrings[tls.VersionTLS10], versionsStrings[tls.VersionTLS11], versionsStrings[tls.VersionTLS12], versionsStrings[tls.VersionTLS13],
		versionsStrings[tls.VersionTLS10], versionsStrings[tls.VersionTLS11], versionsStrings[tls.VersionTLS12], versionsStrings[tls.VersionTLS13],
	)
	_, err = fh.WriteString(csvLine)
	if err != nil {
		panic(err)
	}

	for i, url := range urls {
		fmt.Printf("% 5d: %50s:\t\t", i+1, url)

		// Set defaults for the output.
		testResult := TLSResult{resultUnknown, resultUnknown, resultUnknown, resultUnknown, ``, ``, ``, ``}

		for _, tlsVersion := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {

			var (
				tlsURLResult = resultUnknown // Defaults to 'unknown'.
				tlsURLNote   = ""            // Optional text about the test (e.g. the error encountered).
			)

			client := &http.Client{
				Jar:     jar,
				Timeout: 3 * time.Second,
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
			// request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36")
			request.AddCookie(&http.Cookie{Name: "security", Value: "true", Path: "/"})

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
		fmt.Printf("%s %s %s %s\n", resultsIcons[testResult.tls10], resultsIcons[testResult.tls11], resultsIcons[testResult.tls12], resultsIcons[testResult.tls13])

		csvLine := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			url,
			resultsShortStrings[testResult.tls10],
			resultsShortStrings[testResult.tls11],
			resultsShortStrings[testResult.tls12],
			resultsShortStrings[testResult.tls13],
			testResult.tls10note,
			testResult.tls11note,
			testResult.tls12note,
			testResult.tls13note,
		)

		_, err := fh.WriteString(csvLine)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("Done. Tested %d URLs in %s.\n", len(urls), time.Since(startupTime).Round(time.Millisecond))
}