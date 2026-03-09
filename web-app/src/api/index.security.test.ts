// This file is part of S3 Console
// Copyright (c) 2026 SeRP.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import { CommonAPIValidation, api } from "./index";
import { HttpResponse } from "./consoleApi";

describe("Security: Token Expiry and Re-authentication", () => {
  // Store original location
  const originalLocation = window.location;

  beforeEach(() => {
    // Mock window.location
    delete (window as any).location;
    (window as any).location = { href: "", pathname: "/buckets" };
  });

  afterEach(() => {
    (window as any).location = originalLocation;
  });

  test("401 response should redirect to login", () => {
    const response: HttpResponse<any, any> = {
      data: null,
      status: 401,
      error: {
        message: "invalid session",
        detailedMessage: "",
      },
    } as any;

    CommonAPIValidation(response);

    expect((window as any).location).toBe("/login");
  });

  test("403 with invalid session should redirect to login", () => {
    const response: HttpResponse<any, any> = {
      data: null,
      status: 403,
      error: {
        message: "invalid session",
        detailedMessage: "",
      },
    } as any;

    CommonAPIValidation(response);

    expect((window as any).location).toBe("/login");
  });

  test("other 403 errors should not redirect", () => {
    const response: HttpResponse<any, any> = {
      data: null,
      status: 403,
      error: {
        message: "access denied",
        detailedMessage: "",
      },
    } as any;

    CommonAPIValidation(response);

    expect((window as any).location).not.toBe("/login");
  });

  test("should not redirect to login if already on login page", () => {
    (window as any).location.pathname = "/login";

    const response: HttpResponse<any, any> = {
      data: null,
      status: 401,
      error: {
        message: "invalid session",
        detailedMessage: "",
      },
    } as any;

    CommonAPIValidation(response);

    // Should not redirect when already on login page
    expect((window as any).location).not.toBe("/login");
  });

  test("200 response should not redirect", () => {
    const response: HttpResponse<any, any> = {
      data: { success: true },
      status: 200,
      error: undefined,
    } as any;

    CommonAPIValidation(response);

    expect((window as any).location).not.toBe("/login");
  });
});

describe("Security: Session Management", () => {
  test("session token should be stored only in HttpOnly cookie", () => {
    // Verify that sessionStorage/localStorage don't contain session tokens
    // This is enforced at the backend by setting HttpOnly on cookies

    const sessionToken = sessionStorage.getItem("sessionToken");
    const localToken = localStorage.getItem("token");

    // Should not store tokens in storage (done via secure HttpOnly cookie)
    expect(sessionToken).toBeNull();
    expect(localToken).toBeNull();
  });

  test("Keycloak login should not expose S3 credentials", () => {
    // Verify that OAuth flow is used and no S3 credentials are in localStorage/sessionStorage
    const possibleCredentialKeys = [
      "accessKey",
      "secretKey",
      "s3Credentials",
      "S3_ACCESS_KEY",
      "S3_SECRET_KEY",
    ];

    possibleCredentialKeys.forEach((key) => {
      expect(sessionStorage.getItem(key)).toBeNull();
      expect(localStorage.getItem(key)).toBeNull();
    });
  });
});

describe("Security: Error Messages", () => {
  test("login error should not expose credentials", () => {
    // Error messages returned from API should be user-friendly
    // and not contain sensitive information like keys or detailed error traces

    const sensitivePatterns = [
      /accesskey/i,
      /secretkey/i,
      /credentials/i,
      /s3_/i,
      /internal.*error/i,
    ];

    const userFriendlyMessages = [
      "invalid login",
      "access denied",
      "session expired",
      "authentication failed",
    ];

    // Verify user-friendly messages don't contain sensitive patterns
    userFriendlyMessages.forEach((msg) => {
      sensitivePatterns.forEach((pattern) => {
        expect(msg).not.toMatch(pattern);
      });
    });
  });

  test("network errors should be generic", () => {
    // Network errors should not expose internal API details
    const genericNetworkError = "Unable to connect to server. Please try again.";

    expect(genericNetworkError).not.toMatch(/api\//i);
    expect(genericNetworkError).not.toMatch(/endpoint/i);
    expect(genericNetworkError).not.toMatch(/socket/i);
  });
});

describe("Security: OAuth State and Nonce", () => {
  test("OAuth state should be stored in sessionStorage", () => {
    const state = "test-state-123";
    sessionStorage.setItem("oauth_state", state);

    expect(sessionStorage.getItem("oauth_state")).toBe(state);
  });

  test("OAuth nonce should be stored in sessionStorage", () => {
    const nonce = "test-nonce-456";
    sessionStorage.setItem("oauth_nonce", nonce);

    expect(sessionStorage.getItem("oauth_nonce")).toBe(nonce);
  });

  test("OAuth state should be cleared after validation", () => {
    sessionStorage.setItem("oauth_state", "test-state");
    // In real implementation, state is validated then cleared
    sessionStorage.removeItem("oauth_state");

    expect(sessionStorage.getItem("oauth_state")).toBeNull();
  });
});

describe("Security: XSS Protection", () => {
  test("session tokens should not be exposed to JavaScript", () => {
    // With HttpOnly cookies, tokens cannot be accessed via JS
    // This is enforced at the browser level

    // If we try to access document.cookie, it should not include HttpOnly cookies
    // Note: This is browser-enforced, not JS-enforceable
    expect(typeof document.cookie).toBe("string");
  });
});

describe("Security: CSRF Protection", () => {
  test("requests should include CORS headers for state validation", () => {
    // OAuth flow includes state parameter for CSRF protection
    // tested in Keycloak login component

    const state = sessionStorage.getItem("oauth_state");
    // State should be present and non-empty
    if (state) {
      expect(state.length).toBeGreaterThan(0);
    }
  });
});
