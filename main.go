package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

type Config struct {
	ClientID          string `json:"client_id"`
	UserEmail         string `json:"user_email"`
	ClientSecret      string `json:"client_secret"`
	RefreshToken      string `json:"refresh_token"`
	SubjectPattern    string `json:"subject_pattern"`
	AttachmentPattern string `json:"attachment_pattern"`
}

type Progress struct {
	Timestamp *int64 `json:"progress"`
}

// GetAccessToken exchanges a refresh token for a new access token using Google's OAuth2 endpoint.
func GetAccessToken(clientID, clientSecret, refreshToken string) (string, error) {
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	return tokenResp.AccessToken, nil
}

func main() {
	// Dummy config and progress
	config := Config{
		ClientID:          "",
		UserEmail:         "dgsk@myredstone.com",
		ClientSecret:      "",
		RefreshToken:      "",
		SubjectPattern:    "BBG Final Invoice",
		AttachmentPattern: "",
	}
	var initialTimestamp int64 = 1762501679
	progress := Progress{Timestamp: &initialTimestamp}

	ctx := context.Background()

	// Get access token using refresh token
	accessToken, err := GetAccessToken(config.ClientID, config.ClientSecret, config.RefreshToken)
	if err != nil {
		fmt.Println("Failed to get access token:", err)
		return
	}

	// OAuth2 token with access token
	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: config.RefreshToken,
		TokenType:    "Bearer",
	}

	// OAuth2 config
	oauthCfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		Scopes: []string{gmail.GmailReadonlyScope},
	}

	// Get authenticated client
	client := oauthCfg.Client(ctx, token)

	// Gmail service
	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		fmt.Println("Unable to create Gmail service:", err)
		return
	}

	// Build query
	var query string
	if progress.Timestamp != nil {
		query = fmt.Sprintf("after:%d", *progress.Timestamp)
	}

	// List messages
	msgListCall := srv.Users.Messages.List("me").Q(query)
	msgList, err := msgListCall.Do()
	if err != nil {
		fmt.Println("Unable to retrieve messages:", err)
		return
	}

	// Print total number of messages
	fmt.Printf("Total messages: %d\n", len(msgList.Messages))

	// Reverse messages (older at top)
	sort.Slice(msgList.Messages, func(i, j int) bool {
		return i > j
	})

	var lastTimestamp int64 = 0
	if progress.Timestamp != nil {
		lastTimestamp = *progress.Timestamp
	}

	// Iterate messages
	for _, msg := range msgList.Messages {
		msgDetail, err := srv.Users.Messages.Get("me", msg.Id).Format("metadata").Do()
		if err != nil {
			fmt.Printf("Unable to get message %s: %v\n", msg.Id, err)
			continue
		}

		// internalDate is in milliseconds
		internalDateMillis := msgDetail.InternalDate
		internalDateSecs := internalDateMillis / 1000

		// Ensure new timestamp is greater than previous
		if internalDateSecs > lastTimestamp {
			lastTimestamp = internalDateSecs
			progress.Timestamp = &lastTimestamp
		}
		fmt.Printf("Message ID: %s, internalDate: %d\n", msg.Id, internalDateSecs)
	}

	// Update progress
	progressBytes, _ := json.MarshalIndent(progress, "", "  ")
	_ = ioutil.WriteFile("progress.json", progressBytes, 0644)
	fmt.Printf("Final progress timestamp: %d\n", lastTimestamp)
}