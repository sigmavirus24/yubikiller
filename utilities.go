package yubikiller

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

const (
	yubicoAPIURL   = "https://api.yubico.com/wsapi/2.0/verify?id=1"
	alphabet       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphabetLength = int64(len(alphabet))
)

var letterRunes = []rune(alphabet)

// InvalidateToken accepts the token string and invalidates it via the Yubico
// API
func InvalidateToken(ctx context.Context, token string) error {
	requestURI, err := buildURL(token)
	if err != nil {
		return err
	}
	fmt.Println(requestURI)

	response, err := makeRequest(ctx, requestURI)
	if err != nil {
		return err
	}

	body := bufio.NewReader(response.Body)
	defer response.Body.Close()

	parsedResponse := make(map[string]string)

	for {
		line, err := body.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			parsedResponse[pair[0]] = strings.TrimRight(pair[1], "\r\n")
		}
	}

	if parsedResponse["status"] != "OK" {
		return fmt.Errorf("Yubico API did not successfully invalidate token: %v", parsedResponse)
	}
	// TODO: Decide if we want to do something with the other parameters

	return nil
}

func buildURL(token string) (string, error) {
	yubico, err := url.Parse(yubicoAPIURL)
	if err != nil {
		return "", err
	}
	values := yubico.Query()
	values.Set("otp", token)
	nonce, err := generateNonce()
	if err != nil {
		return "", err
	}
	values.Set("nonce", nonce)
	yubico.RawQuery = values.Encode()

	return yubico.String(), nil
}

func makeRequest(ctx context.Context, uri string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return response, fmt.Errorf("Yubico API returned non-200 response: %v", response)
	}

	return response, nil
}

func generateNonce() (string, error) {
	token := make([]rune, 16)
	max := big.NewInt(alphabetLength)
	for i := range token {
		index, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		token[i] = letterRunes[index.Int64()]
	}

	return string(token), nil
}
