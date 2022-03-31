package com.janeirodigital.sai.authentication;

import com.janeirodigital.sai.httputils.HttpMethod;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.Objects;

import static com.janeirodigital.sai.authentication.AuthorizedSessionHelper.getAccessTokenFromRequest;
import static com.janeirodigital.sai.httputils.HttpHeader.AUTHORIZATION;

/**
 * Leverages the OkHttp
 * <a href="https://square.github.io/okhttp/3.x/okhttp/okhttp3/Authenticator.html">Authenticator API</a>
 * to react to HTTP 401 Not Authorized responses that may arise as a result of an expired or invalid
 * token. Tokens are obtained and refreshed through the {@link AuthorizedSessionAccessor}.
 */
@Slf4j
public class AccessTokenRefresher implements Authenticator {

    private final AuthorizedSessionAccessor sessionAccessor;

    /**
     * Construct a new AccessTokenRefresher
     * @param sessionAccessor {@link AuthorizedSessionAccessor} to use for session lookup
     */
    public AccessTokenRefresher(AuthorizedSessionAccessor sessionAccessor) {
        Objects.requireNonNull(sessionAccessor, "Must supply an authorized session accessor for the access token authenticator");
        this.sessionAccessor = sessionAccessor;
    }

    /**
     * In the event that a request receives a 401 Unauthorized, this method will be automatically called
     * by the OkHttp client (if added during client initialization). If the origin request had provided
     * credentials in the authorization headers, this method will attempt to lookup the corresponding
     * authorized session the token was sourced from, and refresh it for a valid one (choosing the appropriate
     * refresh mechanism based on the protocol associated with the authorized session).
     * This authenticator blocks all requests while an updated token is being obtained.
     * In-flight requests that fail with a 401 are automatically retried.
     * @param route Optional OkHttp Route
     * @param response OkHttp Response
     * @return OkHttp Request with updated token in Authorization header
     */
    @Override
    public Request authenticate(Route route, @NotNull Response response) {

        // If the original request didn't have an authorization header don't bother
        if (response.request().header(AUTHORIZATION.getValue()) != null) {

            // Get the original access token from the request
            AccessToken accessToken = getAccessTokenFromRequest(response.request());
            if (accessToken == null) { return null; }

            AuthorizedSession original = this.sessionAccessor.get(accessToken);
            if (original == null) { return null; }
            // Only one thread at a time will go through this to avoid refresh chaos
            synchronized (this) {

                // Look it up again to see if it has changed since we grabbed the thread lock
                // (e.g. another thread ahead of this one already refreshed it)
                // If it has, retry the request with the new token from the updated session
                AuthorizedSession updated = getAuthorizedSession(original);
                if (updated == null) { return null; }
                if (!original.equals(updated)) { return replaceAuthorizationHeaders(response, updated); }

                // If it hasn't changed, refresh the token and retry the request
                AuthorizedSession refreshed = refreshAuthorizedSession(updated);
                if (refreshed == null) { return null; }
                return replaceAuthorizationHeaders(response, refreshed);
            }
        }
        return null;
    }

    /**
     * Removes any existing authorization headers from the request and adds the updated
     * ones. Supports auth schemes (like DPoP) that have multiple headers.
     * @param response OkHttp Response (original 401)
     * @param session Refreshed session
     * @return Updated OkHttp Request
     */
    protected Request replaceAuthorizationHeaders(Response response, AuthorizedSession session) {
        Request.Builder requestBuilder = response.request().newBuilder();
        Map<String, String> authorizationHeaders;
        try {
            authorizationHeaders = session.toHttpHeaders(HttpMethod.get(response.request().method()), response.request().url().uri());
        } catch (SaiAuthenticationException ex) {
            log.error("Unable to generate authorization headers: " + ex.getMessage());
            return null;
        }
        authorizationHeaders.forEach((header, value) -> requestBuilder.removeHeader(header));
        authorizationHeaders.forEach(requestBuilder::addHeader);
        return requestBuilder.build();
    }

    /**
     * Wrapper around the {@link AuthorizedSessionAccessor} access to handle and log exceptions
     * @param session {@link AuthorizedSession} to get
     * @return {@link AuthorizedSession} or null if nothing was found (or on error)
     */
    private AuthorizedSession getAuthorizedSession(AuthorizedSession session) {
        try { return this.sessionAccessor.get(session); } catch (SaiAuthenticationException ex) {
            log.error("Failed to get authorized session from session storage: " + ex.getMessage());
            return null;
        }
    }

    /**
     * Wrapper around the {@link AuthorizedSessionAccessor} access to handle and log exceptions
     * @param session {@link AuthorizedSession} to refresh
     * @return {@link AuthorizedSession} or null if nothing was found (or on refresh error)
     */
    private AuthorizedSession refreshAuthorizedSession(AuthorizedSession session) {
        try { return this.sessionAccessor.refresh(session); } catch (SaiAuthenticationException ex) {
            log.error("Failed to refresh authorized session via session storage accessor: " + ex.getMessage());
            return null;
        }
    }
}
