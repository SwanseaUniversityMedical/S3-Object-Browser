// This file is part of S3 Console
// Copyright (c) 2026 SeRP.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

import React, { useEffect, useState } from "react";
import { Box, Button, Loader } from "mds";
import { api } from "../../api";

interface KeycloakConfig {
  authorizationUrl: string;
  clientId: string;
  redirectUri: string;
  scopes: string;
}

const KeycloakLogin = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [config, setConfig] = useState<KeycloakConfig | null>(null);

  useEffect(() => {
    // Fetch Keycloak configuration from backend
    fetchKeycloakConfig();
  }, []);

  const fetchKeycloakConfig = async () => {
    try {
      // This endpoint should be added to the backend to provide OAuth config
      const response = await fetch("/api/v1/oauth/config");
      if (!response.ok) {
        throw new Error("Failed to fetch OAuth configuration");
      }
      const data = await response.json();
      setConfig({
        authorizationUrl: data.authorizationUrl,
        clientId: data.clientId,
        redirectUri: data.redirectUri,
        scopes: data.scopes || "openid profile email",
      });
      setLoading(false);
    } catch (err) {
      console.error("Error fetching Keycloak config:", err);
      setError("Unable to load authentication configuration");
      setLoading(false);
    }
  };

  const handleKeycloakLogin = () => {
    if (!config) {
      setError("Configuration not loaded");
      return;
    }

    // Generate state and nonce for security
    const state = generateRandomString(32);
    const nonce = generateRandomString(32);

    // Store state in sessionStorage for validation on callback
    sessionStorage.setItem("oauth_state", state);
    sessionStorage.setItem("oauth_nonce", nonce);
    // Store the IDP config URL for logout - extract base URL from config.authorizationUrl
    const baseUrl = config.authorizationUrl.split("/protocol/")[0];
    sessionStorage.setItem("oauth_idp_url", baseUrl);

    // Build the authorization URL
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: "code",
      scope: config.scopes,
      state: state,
      nonce: nonce,
    });

    const authUrl = `${config.authorizationUrl}?${params.toString()}`;

    // Redirect to Keycloak
    window.location.href = authUrl;
  };

  const generateRandomString = (length: number): string => {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  };

  if (loading) {
    return (
      <Box
        sx={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          minHeight: "200px",
        }}
      >
        <Loader />
      </Box>
    );
  }

  if (error) {
    return (
      <Box
        sx={{
          textAlign: "center",
          padding: "20px",
        }}
      >
        <p style={{ color: "#C83B51", marginBottom: "16px" }}>{error}</p>
        <Button
          id="retry-config"
          onClick={fetchKeycloakConfig}
          variant="callAction"
          label="Retry"
        />
      </Box>
    );
  }

  return (
    <Box
      sx={{
        width: "100%",
        display: "flex",
        flexDirection: "column",
        gap: "16px",
      }}
    >
      <Button
        onClick={handleKeycloakLogin}
        variant="callAction"
        color="primary"
        id="keycloak-login"
        label="Login with Keycloak"
        sx={{
          height: 40,
          width: "100%",
          boxShadow: "none",
          padding: "16px 30px",
        }}
        fullWidth
      />
      <Box
        sx={{
          textAlign: "center",
          fontSize: "12px",
          color: "#888",
          marginTop: "8px",
        }}
      >
        You will be redirected to the identity provider to authenticate.
        <br />
        No credentials are stored in your browser.
      </Box>
    </Box>
  );
};

export default KeycloakLogin;
