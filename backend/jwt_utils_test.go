package backend

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/digitalrebar/provision/models"
)

func TestRandString(t *testing.T) {
	r := randString(16)
	if len(r) != 16 {
		t.Errorf("Random string should be 16 bytes long: %s\n", r)
	}
}

func TestJWTUtils(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "roles")
	testkey := "testhashkey01234testhashkey01234"
	jwtManager := NewJwtManager([]byte(testkey))

	if jwtManager.method != jwt.SigningMethodHS256 {
		t.Errorf("Default signing method wasn't used: %v %v\n", jwt.SigningMethodHS256, jwtManager.method)
	}
	if string(jwtManager.key) != testkey {
		t.Errorf("Key was not set: %v %v\n", testkey, string(jwtManager.key))
	}

	jwtManager = NewJwtManager([]byte(testkey), JwtConfig{Method: jwt.SigningMethodRS512})
	if jwtManager.method != jwt.SigningMethodRS512 {
		t.Errorf("Default signing method wasn't used: %v %v\n", jwt.SigningMethodRS512, jwtManager.method)
	}
	if string(jwtManager.key) != testkey {
		t.Errorf("Key was not set: %v %v\n", testkey, string(jwtManager.key))
	}

	jwtManager = NewJwtManager([]byte(randString(32)))
	s, e := NewClaim("fred", "fred", 30).AddRawClaim("*", "get", "m").Seal(jwtManager)
	if e != nil {
		t.Errorf("Failed to sign token: %v\n", e)
	}
	drpClaim, e := jwtManager.get(s)
	if e != nil {
		t.Errorf("Failed to get token: %v\n", e)
	} else {
		if drpClaim.Id != "fred" {
			t.Errorf("Claim ID doesn't match: %v %v\n", "fred", drpClaim.Id)
		}
		if !drpClaim.match(rt, models.MakeRole("", "bootenvs", "get", "m")) {
			t.Errorf("Claim Scope doesn't match: %v %v\n", []string{"bootenvs", "get", "m"}, drpClaim)
		}
	}

	s, e = NewClaim("fred", "fred", 1).AddRawClaim("*", "get", "a").Seal(jwtManager)
	if e != nil {
		t.Errorf("Failed to sign token: %v\n", e)
	}
	time.Sleep(1000 * 1000 * 1000 * 3)
	drpClaim, e = jwtManager.get(s)
	if e == nil {
		t.Errorf("Failed because we got a token: %v\n", drpClaim)
	}
}
