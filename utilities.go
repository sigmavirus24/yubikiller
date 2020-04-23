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

	errorFmt := "failed to invalidate the token: %s (%v)"
	// https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html
	switch parsedResponse["status"] {
	case "OK":
		return nil
	case "BAD_OTP":
		return fmt.Errorf(errorFmt, "The OTP is in an invalid format", parsedResponse)
	case "REPLAYED_OTP":
		return fmt.Errorf(errorFmt, "The token has already been seen", parsedResponse)
	case "BAD_SIGNATURE":
		return fmt.Errorf(errorFmt, "The HMAC signature verification failed", parsedResponse)
	case "MISSING_PARAMETER":
		return fmt.Errorf(errorFmt, "The request is missing a parameter", parsedResponse)
	case "NO_SUCH_CLIENT":
		return fmt.Errorf(errorFmt, "The request id does not exist", parsedResponse)
	case "OPERATION_NOT_ALLOWED":
		return fmt.Errorf(errorFmt, "The request id is not allowed to verify OTPs", parsedResponse)
	case "BACKEND_ERROR":
		return fmt.Errorf(errorFmt, "Unexpected server error", parsedResponse)
	case "NOT_ENOUGH_ANSWERS":
		return fmt.Errorf(errorFmt, "Server could not get requested number of syncs during before timeout", parsedResponse)
	case "REPLAYED_REQUEST":
		return fmt.Errorf(errorFmt, "Server has seen the OTP/Nonce combination before", parsedResponse)
	default:
		return fmt.Errorf("Yubico API did not successfully invalidate token: %v", parsedResponse)
	}
	// TODO: Decide if we want to do something with the other parameters
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
