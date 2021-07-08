// +build integration

package main

import (
	"net/http"
	"testing"

	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
)

func TestLogin(t *testing.T) {
	assertEnv("JWT_URL")
	apitest.New().
		Handler(apiLogin(db)).
		Post("/api/v0/login").
		Header("Authorization", "Basic ZXJuc3Q6ZXJuc3Q="). // Base 64 encoding of "ernst:ernst"
		Expect(t).
		Assert(jsonpath.Present("access_token")).
		Status(http.StatusOK).
		End()
}
