// This file is part of Object Browser
// Copyright (c) 2026 Object Browser Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// OAuthConfigHandler returns the OAuth configuration for the frontend
func OAuthConfigHandler(w http.ResponseWriter, r *http.Request) {
	// Get configuration from environment variables
	// Use public URL for browser redirects, fallback to internal URL
	publicIssuerURL := os.Getenv("CONSOLE_IDP_PUBLIC_URL")
	if publicIssuerURL == "" {
		// Fallback to internal URL (for backward compatibility)
		publicIssuerURL = os.Getenv("CONSOLE_IDP_URL")
		if publicIssuerURL == "" {
			publicIssuerURL = KeycloakOIDCConfig.IssuerURL
		}
	}

	clientID := os.Getenv("CONSOLE_IDP_CLIENT_ID")
	if clientID == "" {
		clientID = KeycloakOIDCConfig.ClientID
	}

	redirectURI := os.Getenv("CONSOLE_IDP_CALLBACK")
	if redirectURI == "" {
		redirectURI = KeycloakOIDCConfig.RedirectURI
	}

	scopes := os.Getenv("CONSOLE_IDP_SCOPES")
	if scopes == "" {
		scopes = "openid profile email"
	}

	// Build authorization URL using public URL for browser access
	authorizationURL := fmt.Sprintf("%s/protocol/openid-connect/auth", publicIssuerURL)

	config := map[string]string{
		"authorizationUrl": authorizationURL,
		"clientId":         clientID,
		"redirectUri":      redirectURI,
		"scopes":           scopes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// OAuthCallbackRequest represents the OAuth callback request from the frontend
type OAuthCallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// OAuthCallbackResponse represents the response sent to the frontend
type OAuthCallbackResponse struct {
	SessionID string `json:"sessionId"`
	UserEmail string `json:"userEmail,omitempty"`
	Success   bool   `json:"success"`
}

// OAuthCallbackHandler handles the OAuth callback from the frontend
func OAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("DEBUG: OAuthCallbackHandler called - Method: %s, Path: %s\n", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		fmt.Printf("ERROR: Wrong method: %s\n", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req OAuthCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Printf("ERROR: Failed to decode request body: %v\n", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fmt.Printf("DEBUG: Received auth code: %s, state: %s\n", req.Code[:10]+"...", req.State)

	if req.Code == "" {
		fmt.Printf("ERROR: Empty authorization code\n")
		http.Error(w, "Authorization code is required", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens
	fmt.Printf("DEBUG: Calling AuthenticateWithKeycloak...\n")
	loginResponse, err := AuthenticateWithKeycloak(req.Code)
	if err != nil {
		fmt.Printf("ERROR: AuthenticateWithKeycloak failed: %v\n", err)
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	fmt.Printf("DEBUG: Authentication successful, setting cookie...\n")

	// Set session cookie
	cookie := NewSessionCookieForConsole(loginResponse.SessionID)
	fmt.Printf("DEBUG: Cookie details - Name: %s, Path: %s, HttpOnly: %v, SameSite: %v, Secure: %v\n",
		cookie.Name, cookie.Path, cookie.HttpOnly, cookie.SameSite, cookie.Secure)
	http.SetCookie(w, &cookie)

	// Return success response
	response := OAuthCallbackResponse{
		SessionID: loginResponse.SessionID,
		Success:   true,
	}

	fmt.Printf("DEBUG: Sending success response\n")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
