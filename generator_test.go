package fireauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	gen := New("foo")
	if gen == nil {
		t.Fatal("generator should not be nil")
	}
}

func TestCreateToken_Data(t *testing.T) {
	gen := New("foo")
	data := Data{"uid": "1"}
	token, err := gen.CreateToken(data, nil)
	if err != nil {
		t.Fatal(err)
	}

	tokenParts := strings.Split(token, TokenSep)
	if len(tokenParts) != 3 {
		t.Fatal("token is not composed correctly")
	}

	bytes, err := base64.URLEncoding.DecodeString(tokenParts[1] + "==")
	if err != nil {
		t.Fatal(err)
	}

	claim := struct {
		Version  int   `json:"v"`
		Data     Data  `json:"d"`
		IssuedAt int64 `json:"iat"`
	}{}
	if err := json.Unmarshal(bytes, &claim); err != nil {
		t.Fatal(err)
	}

	if claim.Version != Version {
		t.Fatal("Expected: %d\nActual: %d", Version, claim.Version)
	}

	if !reflect.DeepEqual(data, claim.Data) {
		t.Fatalf("auth data is not the same.Expected: %s\nActual: %s", data, claim.Data)
	}
}

func TestCreateToken_NoData(t *testing.T) {
	gen := New("foo")
	if _, err := gen.CreateToken(nil, nil); err == nil {
		t.Fatal(err)
	}
}

func TestCreateToken_Admin_NoData(t *testing.T) {
	gen := New("foo")
	options := &Option{
		Admin: true,
	}
	if _, err := gen.CreateToken(nil, options); err != nil {
		t.Fatal(err)
	}
}

func TestCreateToken_TooLong(t *testing.T) {
	gen := New("foo")
	data := Data{"uid": "1", "bigKey": randData(1024)}
	if _, err := gen.CreateToken(data, nil); err == nil {
		t.Fatal("should have failed")
	}
}

func randData(size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}
