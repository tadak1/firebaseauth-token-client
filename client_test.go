package authtokenclient

import (
	"github.com/google/go-cmp/cmp"
	"net/url"
	"os"
	"testing"
)

func TestFirebaseAuthTokenClient_Token(t *testing.T) {
	client, err := NewFirebaseAuthTokenClient()
	if err != nil {
		t.Fatal(err)
	}
	type args struct {
		body *SignInWithPasswordPayload
	}
	tests := []struct {
		name    string
		args    args
		isEmpty bool
		wantErr bool
	}{
		{
			name: "Should get id token",
			args: args{
				body: &SignInWithPasswordPayload{
					Email:             "test@example.com",
					Password:          "secretPassword",
					ReturnSecureToken: false,
				},
			},
			isEmpty: false,
			wantErr: false,
		},
		{
			name: "Should not get id token when invalid body",
			args: args{
				body: &SignInWithPasswordPayload{
					Email:             "invalid",
					Password:          "invalid",
					ReturnSecureToken: false,
				},
			},
			isEmpty: true,
			wantErr: true,
		},
		{
			name: "Should not get id token when nil value",
			args: args{
				body: nil,
			},
			isEmpty: true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.Token(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got != "") == tt.isEmpty {
				t.Errorf("token=%s isEmpty %v ", got, tt.isEmpty)
			}
		})
	}
}

func TestFirebaseAuthTokenClient_destinationURL(t *testing.T) {
	type fields struct {
		URL url.URL
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Should get destination url",
			fields: fields{
				URL: url.URL{
					Scheme:   httpsVar,
					Host:     firebaseAuthHostVar,
					Path:     firebaseSignInPathVar,
					RawQuery: "key=API_KEY",
				},
			},
			want: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=API_KEY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &FirebaseAuthTokenClient{
				URL: tt.fields.URL,
			}
			if got := client.destinationURL(); got != tt.want {
				t.Errorf("destinationURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFirebaseAuthTokenClient(t *testing.T) {
	tests := []struct {
		name    string
		onSetup func()
		want    *FirebaseAuthTokenClient
		wantErr bool
	}{
		{
			name: "Should get firebase auth token client",
			onSetup: func() {
				os.Setenv(firebaseApiKeyVar, "API_KEY")
			},
			want: &FirebaseAuthTokenClient{
				URL: url.URL{
					Scheme:   httpsVar,
					Host:     firebaseAuthHostVar,
					Path:     firebaseSignInPathVar,
					RawQuery: "key=API_KEY",
				},
			},
			wantErr: false,
		},
		{
			name: "Should get firebase auth token client for local",
			onSetup: func() {
				os.Setenv(firebaseApiKeyVar, "API_KEY")
				os.Setenv(firebaseAuthEmulatorHostVar, "0.0.0.0:9099")
			},
			want: &FirebaseAuthTokenClient{
				URL: url.URL{
					Scheme:   httpVar,
					Host:     "0.0.0.0:9099",
					Path:     firebaseSignInPathVar,
					RawQuery: "key=API_KEY",
				},
			},
			wantErr: false,
		},
		{
			name: "Should not get firebase auth token client",
			onSetup: func() {
				os.Setenv(firebaseApiKeyVar, "")
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.onSetup()
			got, err := NewFirebaseAuthTokenClient()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFirebaseAuthTokenClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("NewFirebaseAuthTokenClient diff: (-got +want)\n%s", diff)
			}
		})
	}
}
