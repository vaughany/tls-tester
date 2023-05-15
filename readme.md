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
2. Run it with e.g. `./tls-tester` or `tls-tester.exe`

---

## Command-line Options 

By default, the program will scan four common URLs.  Run the command with `-url your-domain.com` to scan a URL of your choice.

Run the command with `-h` for help.

---

## On-screen Output

Typical on-screen output looks like this, with the URL being tested and the results of the TLS 1.0, 1.1, 1.2 and 1.3 tests running left to right.

Remember that ideally, we want to see TLS 1.2 or 1.3, and **do not want** to see TLS 1.0 or 1.1.

```bash
TLS Tester v0.1
Checking 4 URLs for TLS security
  1:     apple.com:  ✅ ✅ ✅ ✅
  2:  facebook.com:  ❌ ❌ ✅ ✅
  3:    google.com:  ❌ ❌ ✅ ✅
  4:   twitter.com:  ✅ ✅ ✅ ✅
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

## Double checking

This is a basic tool, reporting only basic results. The results are neither definitive or conclusive, and errors especially may be the results of timeouts due to slow-running Internet between you and the target, as well as more mundane things. Looking deeper into your security is highly recommended.

1. If you're on Linux or MacOS, I suggest downloading `testssl.sh` from [testssl.sh](https://testssl.sh/) and testing your domains against it.  
2. Alternatively, use SSL Labs' [SSl Test](https://www.ssllabs.com/ssltest/) (but remember to tick the 'keep results private' box).

---

## Version History

* **2022-05-15, v0.1:** initial release. Scans four common URLs by default or use `-url` to scan a URL of your choice.
* **2022-05-15, v0.2:** used goroutines and waitgroups to run the four TLS version tests concurrently-per-URL, significantly reducing the testing time.

---

## To-Do

1. Refactor the code to use multiple workers / queues, so the process can be completed much faster if scanning many URLs.
