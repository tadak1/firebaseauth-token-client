package authtokenclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

const (
	httpVar                     = "http"
	httpsVar                    = "https"
	firebaseApiKeyVar           = "FIREBASE_API_KEY"
	firebaseAuthEmulatorHostVar = "FIREBASE_AUTH_EMULATOR_HOST"
	firebaseAuthHostVar         = "identitytoolkit.googleapis.com"
	firebaseSignInPathVar       = "v1/accounts:signInWithPassword"
)

type FirebaseAuthTokenClient struct {
	URL url.URL
}

type SignInWithPasswordPayload struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type SignInWithPasswordResponse struct {
	IdToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalId      string `json:"localId"`
	Registered   bool   `json:"registered"`
}

func NewFirebaseAuthTokenClient() (*FirebaseAuthTokenClient, error) {
	apiKey := os.Getenv(firebaseApiKeyVar)
	if apiKey == "" {
		return nil, fmt.Errorf("firebase apikey is not specified")
	}
	destinationURL := url.URL{
		Scheme:   httpsVar,
		Host:     firebaseAuthHostVar,
		Path:     firebaseSignInPathVar,
		RawQuery: "key=" + apiKey,
	}
	emulatorAuthHost := os.Getenv(firebaseAuthEmulatorHostVar)
	if emulatorAuthHost != "" {
		destinationURL.Scheme = httpVar
		destinationURL.Host = emulatorAuthHost
	}
	return &FirebaseAuthTokenClient{
		URL: destinationURL,
	}, nil
}

func (client *FirebaseAuthTokenClient) destinationURL() string {
	return client.URL.String()
}

func (client *FirebaseAuthTokenClient) Token(body *SignInWithPasswordPayload) (string, error) {
	if body == nil {
		return "", fmt.Errorf("body is nil")
	}
	requestBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	uri := client.destinationURL()
	response, err := http.Post(uri, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request not succeed")
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	signInResponse := &SignInWithPasswordResponse{}
	if err := json.Unmarshal(bodyBytes, signInResponse); err != nil {
		return "", err
	}
	return signInResponse.IdToken, nil
}
