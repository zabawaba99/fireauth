# Fireauth
---
[![Build Status](https://travis-ci.org/zabawaba99/fireauth.svg?branch=master)](https://travis-ci.org/zabawaba99/fireauth) [![Coverage Status](https://coveralls.io/repos/zabawaba99/fireauth/badge.svg?branch=master)](https://coveralls.io/r/zabawaba99/fireauth?branch=master)
---

A Firebase token generator written in Go

## Installation

```bash
go get -u github.com/zabawaba99/fireauth
```

## Usage

Import fireauth

```go
import "github.com/zabawaba99/fireauth"
```

Create a TokenGenerator

```go
gen := fireauth.New("foo")
```

Generate a token

```go
data := fireauth.Data{"uid": "1"}
token, err := gen.CreateToken(data, nil)
if err != nil {
  log.Fatal(err)
}
println("my token: ",token)
```

### Options

You can also create a token with options

```go
data := fireauth.Data{"uid": "1"}
options := &fireauth.Option{
  NotBefore: 2,
  Expiration: 3,
  Admin: false,
  Debug: true,
}
token, err := gen.CreateToken(data, options)
if err != nil {
  log.Fatal(err)
}
println("my token: ",token)
```

Check the [GoDocs](http://godoc.org/github.com/zabawaba99/fireauth) or
[Firebase Auth Documentation](https://www.firebase.com/docs/rest/guide/user-auth.html#section-overview) for more details

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b new-feature`)
3. Commit your changes (`git commit -am 'Some cool reflection'`)
4. Push to the branch (`git push origin new-feature`)
5. Create new Pull Request
