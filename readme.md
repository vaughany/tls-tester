# TLS Tester

[TLS versions 1.0 and 1.1 were deprecated in 2021](https://en.wikipedia.org/wiki/Transport_Layer_Security#History_and_development) and should no longer be used, preferring instead TLS 1.2 or 1.3.  

I needed to see which versions of TLS a web server would respond to.

TLS Tester connects to a given URL with all four versions of TLS and logs the result.

---

## Getting It and Running It

### Build from source

1. Have [Go installed](https://go.dev/doc/install).
2. Clone [this repository (github.com/vaughany/tls-tester)](https://github.com/vaughany/tls-tester).
3. Run with `go run .`

## Using a pre-built binary

1. [Download a binary](https://github.com/vaughany/tls-tester/releases) for Linux or Windows.
2. Make it executable 
   * Linux: `chmod +x tls-tester`
   * Windows: right-click on it, Properties, Unblock (IIRC).
3. Run it with e.g. `./tls-tester` or `tls-tester.exe`

---

## Command-line Options 

By default, the program will scan four common URLs, purely for example.  Run the command with `-url your-domain.com` to scan a URL of your choice.

Run the command with `-h` for help.

---

## On-screen Output

Typical on-screen output looks like this, with the URL being tested and the results of the TLS 1.0, 1.1, 1.2 and 1.3 tests running left to right.

Remember that ideally, we want to see TLS 1.2 or 1.3, and **do not want** to see TLS 1.0 or 1.1.

```bash
TLS Tester v0.4
Checking 4 URLs for TLS security
Starting web server on http://localhost:8080
    Processing apple.com...
    Processing twitter.com...
    Processing google.com...
    Processing facebook.com...
Processing complete.

    1:     apple.com:  ✅ ✅ ✅ ✅
    2:  facebook.com:  ❌ ❌ ✅ ✅
    3:    google.com:  ❌ ❌ ✅ ✅
    4:   twitter.com:  ✅ ✅ ✅ ✅

Done. Tested 4 URLs in 688ms. Check the website on http://localhost:8080 for details.
```

The icons indicate:

```bash
                        |  |  |  |
                        |  |  |  +- TLS 1.3
                        |  |  +---- TLS 1.2
                        |  +------- TLS 1.1
                        +---------- TLS 1.0
```

* If TLS 1.0 or 1.1 are in use, a ❌ is shown in that column.
* If TLS 1.0 or 1.1 are **not** in use, a ✅ is shown in that column.
* If TLS 1.2 or 1.3 are in use, a ✅ is shown.
* If TLS 1.2 or 1.3 are **not** in use, a ❌ is shown.
* If the result of the test was inconclusive or something went wrong, a ❓ is shown.

...so we can see from the test on facebook.com and google.com that TLS versions 1.0 and 1.1 are still offered and that 1.2 and 1.3 are also available. apple.com and twitter.com disallow 1.0 and 1.1 and use 1.2 and 1.3.

To put this another way: 

* an ❌ in either or both of the first two columns means that your web server is using a deprecated TLS version.
* an ❌ in either or both of the last two columns means that your web server is **not** using TLS 1.2 or 1.3, the only two TLS versions which are secure and not deprecated. 

...both of which mean that your web server requires attention.

Ideally, you want to see ✅ ✅ ✅ ✅ for every domain you test.

---

## CSV Output

The results of the current test run are saved to comma-delimited `output.csv` in the current folder with 'okay' and 'not okay' in place of the icons. There are also 'notes' columns showing a note for why that particular test failed.  A lack of note is not an error, just that the 'okay' or 'not okay' is expected behaviour.

```bash
URL,TLS 1.0,TLS 1.1,TLS 1.2,TLS 1.3,TLS 1.0 note,TLS 1.1 note,TLS 1.2 note,TLS 1.3 note
apple.com,okay,okay,okay,okay,protocol version not supported,protocol version not supported,,
facebook.com,not okay,not okay,okay,okay,,,,
google.com,not okay,not okay,okay,okay,,,,
twitter.com,okay,okay,okay,okay,protocol version not supported,protocol version not supported,,
```

**Note:** if the file already exists, it is overwritten.

---

## Web Output

When run, the program will attempt to start a very basic web server on http://localhost:8080 (the on-screen output will mention this both at startup and at the end of the scan). It shows the URL, the results of the tests for all four TLS versions, and a complimentary link to [Qualys' SSL Labs](https://www.ssllabs.com/) with the URL pre-filled, should you want to test your URLs further.

If you test a large number of URLs, they should appear on the web page as soon as that URL has been fully tested. Simply hit refresh on your browser to update it.

The page is formatted using minimal [Bootstrap](https://getbootstrap.com) markup, and pulls the required CSS and JS from a CDN. The page will look much more basic without it.

The CSV data is also available to copy and paste elsewhere, via the web: http://localhost:8080/csv.

Press `Ctrl-C` to quit.

---

## Double checking

This is a basic tool, reporting only basic results. The results are neither definitive or conclusive, and errors especially may be the results of timeouts due to slow-running Internet between you and the target, as well as more mundane things. Looking deeper into your security is highly recommended.

1. If you're on Linux or MacOS, I suggest downloading `testssl.sh` from [testssl.sh](https://testssl.sh/) and testing your domains against it.  
2. Alternatively, use [Qualys' SSL Labs SSL Tester](https://www.ssllabs.com/ssltest/) (but remember to tick the 'keep results private' box).

---

## Version History

* **2022-05-15, v0.1:** initial release. Scans four common URLs by default or use `-url` to scan a URL of your choice.
* **2022-05-15, v0.2:** used goroutines and waitgroups to run the four TLS version tests concurrently-per-URL, significantly reducing the testing time.
* **2022-05-16, v0.3:** refactored the code to use multiple (10) workers / queues, so the process can be completed much faster if scanning many URLs.
* **2022-05-17, v0.4:** Now with a web server (http://localhost:8080) for better presentation of the results.

---

## To-Do

1. Percentages of TLS version use.
2. Use e.g. `input.csv` file in order to specify multiple URLs to test.
3. Processing time on the web page.
