package muser

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/harlow/authtoken"
)

const accesPath = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="

type googleAuthResponse struct {
	Aud           string
	ExpiresIn     string `json:"expires_in"`
	Scope         string
	Email         string
	EmailVerified string `json:"email_verified"`
}

// GetMailByToken -
func GetMailByToken(r *http.Request) (string, error) {
	// ctx := r.Context()
	// client := urlfetch.Client(ctx)
	token, err := authtoken.FromRequest(r)
	if err != nil {
		log.Printf("token from request error: %v", err)
		return "", err
	}
	resp, err := http.Get(accesPath + token)
	if err != nil {
		log.Printf("token check error: %v", err)
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Printf("ioutil.ReadAll error: %v", err)
		return "", err
	}

	answer := new(googleAuthResponse)
	err = json.Unmarshal(body, answer)
	if err != nil {
		log.Printf("json.Unmarashal error: %v", err)
		return "", err
	}

	expires, err := strconv.Atoi(answer.ExpiresIn)
	if err != nil {
		log.Printf("strconv.Atoi(expires) error: %v", err)
		return "", err
	}
	if expires > 0 {
		return answer.Email, nil
	}
	return "", errors.New("Token expired")
}
