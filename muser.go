package muser

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/harlow/authtoken"
	"google.golang.org/appengine"
	glog "google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
)

const accesPath = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="

var adminEmails []string

func init() {
	adminEmails = append(adminEmails, "melifarowow@gmail.com")
}

type googleAuthResponse struct {
	Aud           string
	ExpiresIn     string `json:"expires_in"`
	Scope         string
	Email         string
	EmailVerified string `json:"email_verified"`
}

func IsAdmin(r *http.Request) (bool, error) {
	ctx := appengine.NewContext(r)
	client := urlfetch.Client(ctx)
	token, err := authtoken.FromRequest(r)
	if err != nil {
		glog.Errorf(ctx, "token from request error: %v", err)
		return false, err
	}
	resp, err := client.Get(accesPath + token)
	if err != nil {
		glog.Errorf(ctx, "token check error: %v", err)
		return false, err
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		glog.Errorf(ctx, "ioutil.ReadAll error: %v", err)
		return false, err
	}

	answer := new(googleAuthResponse)
	err = json.Unmarshal(body, answer)
	if err != nil {
		glog.Errorf(ctx, "json.Unmarashal error: %v", err)
		return false, err
	}

	expires, err := strconv.Atoi(answer.ExpiresIn)
	if err != nil {
		glog.Errorf(ctx, "strconv.Atoi(expires) error: %v", err)
		return false, err
	}
	if expires > 0 {
		for _, email := range adminEmails {
			if strings.Compare(email, answer.Email) == 0 {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("Token expired")
}
