// This file is part of S3 Console
// Copyright (c) 2026 SeRP.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Box, Loader } from "mds";
import { useAppDispatch } from "../../store";
import { setErrorSnackMessage, userLogged } from "../../systemSlice";
import { getTargetPath } from "./Login";

const OAuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const [status, setStatus] = useState<string>("Processing authentication...");

  useEffect(() => {
    handleOAuthCallback();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleOAuthCallback = async () => {
    try {
      // Get authorization code and state from URL
      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const error = searchParams.get("error");
      const errorDescription = searchParams.get("error_description");

      // Handle OAuth errors
      if (error) {
        throw new Error(errorDescription || error);
      }

      if (!code) {
        throw new Error("No authorization code received");
      }

      // Validate state to prevent CSRF attacks
      const storedState = sessionStorage.getItem("oauth_state");
      if (!storedState || storedState !== state) {
        throw new Error("Invalid state parameter - possible CSRF attack");
      }

      // Clear stored state
      sessionStorage.removeItem("oauth_state");
      sessionStorage.removeItem("oauth_nonce");

      setStatus("Exchanging authorization code...");

      // Exchange code for session token with backend
      const response = await fetch("/api/v1/oauth/callback", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: code,
          state: state,
        }),
        credentials: "include", // Important: include cookies
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.message || "Failed to complete authentication"
        );
      }

      const data = await response.json();

      setStatus("Authentication successful! Redirecting...");

      // Set user as logged in
      dispatch(userLogged(true));
      
      // Store minimal session info (no credentials)
      if (data.userEmail) {
        localStorage.setItem("userLoggedIn", data.userEmail);
      }

      // Redirect to target path
      const targetPath = getTargetPath();
      
      setTimeout(() => {
        navigate(targetPath);
      }, 500);
    } catch (error: any) {
      console.error("OAuth callback error:", error);
      dispatch(
        setErrorSnackMessage({
          errorMessage: error.message || "Authentication failed",
          detailedError: error.toString(),
        })
      );
      
      // Redirect back to login after error
      setTimeout(() => {
        navigate("/login");
      }, 2000);
    }
  };

  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "100vh",
        gap: "24px",
      }}
    >
      <Loader style={{ width: 60, height: 60 }} />
      <Box
        sx={{
          fontSize: "16px",
          color: "#666",
          textAlign: "center",
        }}
      >
        {status}
      </Box>
    </Box>
  );
};

export default OAuthCallback;
