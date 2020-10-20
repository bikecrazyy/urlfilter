[![Build Status](https://travis-ci.com/bikecrazyy/urlfilter.svg?branch=master)](https://travis-ci.com/bikecrazyy/urlfilter)
[![Code Coverage](https://img.shields.io/codecov/c/github/bikecrazyy/urlfilter/master.svg)](https://codecov.io/github/bikecrazyy/urlfilter?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/bikecrazyy/urlfilter)](https://goreportcard.com/report/bikecrazyy/urlfilter)
[![GolangCI](https://golangci.com/badges/github.com/bikecrazyy/urlfilter.svg)](https://golangci.com/r/github.com/bikecrazyy/urlfilter)
[![Go Doc](https://godoc.org/github.com/bikecrazyy/urlfilter?status.svg)](https://godoc.org/github.com/bikecrazyy/urlfilter)

# AdGuard content blocking library

Pure GO library that implements AdGuard filtering rules syntax.

You can learn more about AdGuard filtering rules syntax from [this article](https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters).

#### TODO:

- [x] Basic filtering rules
  - [x] Core blocking syntax
  - [x] Basic engine
  - [x] Basic rules validation (don't match everything, unexpected modifiers, etc)
  - [ ] Domain modifier semantics: https://github.com/AdguardTeam/AdguardBrowserExtension/issues/1474
  - [ ] TLD support: https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#wildcard-for-tld
- [x] Benchmark basic rules matching
- [x] Hosts matching rules
  - [x] /etc/hosts matching
  - [x] \$badfilter support for host-blocking network rules
- [x] Memory optimization
- [ ] Tech document
- [ ] Cosmetic rules
  - [x] Basic element hiding and CSS rules
    - [ ] Proper CSS rules validation
  - [ ] ExtCSS rules
    - [ ] ExtCSS rules validation
  - [ ] Scriptlet rules
  - [ ] JS rules
- [ ] Proxy implementation
  - [x] Simple MITM proxy example
  - [x] Add cosmetic filters to the proxy example
  - [x] Handling cosmetic modifiers $elemhide, $generichide, \$jsinject
  - [x] (!) Server certificate verification - it should pass badssl.com/dashboard/
  - [ ] Use fetch metadata to detect the content type: https://www.w3.org/TR/fetch-metadata/
  - [ ] Unit tests coverage
  - [ ] Fix TODOs
  - [ ] Proxy - handle CSP (including <meta> tags with CSP)
  - [x] Proxy - proper blocking page code
  - [ ] Proxy - unblocking via a temporary cookie
  - [x] Proxy - content script caching
  - [x] Proxy - content script compression
  - [ ] Proxy - brotli support (see [here](https://github.com/andybalholm/brotli))
  - [ ] Content script - babel plugin
  - [ ] Content script - apply ExtCSS rules
  - [ ] Content script - styles protection
  - [ ] Content script - JS unit tests
  - [ ] Content script - GO unit tests
- [ ] HTML filtering rules
- [ ] Advanced modifiers
  - [x] \$important
  - [ ] \$replace
  - [ ] \$csp
  - [ ] \$cookie
  - [ ] \$redirect
  - [x] \$badfilter
  - [ ] \$badfilter (https://github.com/AdguardTeam/CoreLibs/issues/1241)
  - [ ] \$ping modifier (https://github.com/AdguardTeam/CoreLibs/issues/1258)

#### How to use

TODO
