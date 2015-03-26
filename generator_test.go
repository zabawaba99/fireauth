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
	if gen := New("foo"); gen == nil {
		t.Fatal("generator should not be nil")
	}
}

func TestCreateTokenData(t *testing.T) {
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
		t.Fatalf("Expected: %d\nActual: %d", Version, claim.Version)
	}

	if !reflect.DeepEqual(data, claim.Data) {
		t.Fatalf("auth data is not the same.Expected: %s\nActual: %s", data, claim.Data)
	}
}

func TestCreateTokenNoData(t *testing.T) {
	if _, err := New("foo").CreateToken(nil, nil); err == nil {
		t.Fatal("CreateToken without data nor option should fail")
	}
}

func TestCreateTokenAdminNoData(t *testing.T) {
	if _, err := New("foo").CreateToken(nil, &Option{Admin: true}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateTokenTooLong(t *testing.T) {
	if _, err := New("foo").CreateToken(Data{"uid": "1", "bigKey": randData(t, 1024)}, nil); err == nil {
		t.Fatal("Token too long should have failed")
	}
}

func randData(t *testing.T, size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
	}
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}
