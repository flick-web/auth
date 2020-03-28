package auth_test

import (
	"testing"

	"github.com/flick-web/auth"
)

func TestPasswordChecking(t *testing.T) {
	lm := &auth.LoginManager{BcryptCost: 10}
	hash, err := lm.GetHash("testpassword")
	if err != nil {
		t.Error(err)
	}

	valid := lm.CheckPassword("testpassword", hash)
	if !valid {
		t.Error("Should have been valid")
	}

	valid = lm.CheckPassword("testpasswor", hash)
	if valid {
		t.Error("Should not have been valid")
	}

	valid = lm.CheckPassword("estpassword", hash)
	if valid {
		t.Error("Should not have been valid")
	}

	valid = lm.CheckPassword("", hash)
	if valid {
		t.Error("Should not have been valid")
	}
}

func TestJWTs(t *testing.T) {
	signer := auth.NewTokenSigner("dispatch", []byte("GcWik@!FN2s@xZK#rXh&FkLM9b^dGLQs"))
	token, err := signer.CreateToken("testuser")
	if err != nil {
		t.Error(err)
	}

	claims, err := signer.ParseToken(token)
	if err != nil {
		t.Error(err)
	}
	if claims.Subject != "testuser" {
		t.Errorf("Incorrect sub: %s\n", claims.Subject)
	}
	if claims.Issuer != "dispatch" {
		t.Errorf("Incorrect issuer: %s\n", claims.Issuer)
	}

	token = "badstring" + token
	claims, err = signer.ParseToken(token)
	if err == nil {
		t.Error("Expected error")
	}
}
