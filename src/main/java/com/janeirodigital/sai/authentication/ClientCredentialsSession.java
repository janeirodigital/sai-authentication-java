package com.janeirodigital.sai.authentication;

import com.janeirodigital.sai.httputils.HttpMethod;
import com.janeirodigital.sai.httputils.SaiHttpException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.janeirodigital.sai.authentication.AuthorizedSessionHelper.getOIDCProviderConfiguration;
import static com.janeirodigital.sai.authentication.AuthorizedSessionHelper.translateAccessToken;
import static com.janeirodigital.sai.httputils.HttpHeader.AUTHORIZATION;
import static com.janeirodigital.sai.httputils.HttpUtils.*;

/**
 * Implementation of {@link AuthorizedSession} for a Client Credentials authorization flow
 */
@Getter
public class ClientCredentialsSession implements AuthorizedSession {

    private final URL socialAgentId;
    private final URL applicationId;
    private final String clientIdentifier;
    private final String clientSecret;
    private final URL oidcProviderId;
    private final URL oidcTokenEndpoint;
    private final Scope scope;
    private AccessToken accessToken;

    private ClientCredentialsSession(URL socialAgentId, URL applicationId, String clientIdentifier, String clientSecret, URL oidcProviderId,
                                     URL oidcTokenEndpoint, Scope scope, AccessToken accessToken) throws SaiHttpException {
        Objects.requireNonNull(clientIdentifier, "Must provide an OIDC client identifier to construct a client credentials session");
        Objects.requireNonNull(clientSecret, "Must provide an OIDC client secret to construct a client credentials session");
        Objects.requireNonNull(oidcProviderId, "Must provide an OIDC provider identifier to construct a client credentials session");
        Objects.requireNonNull(oidcTokenEndpoint, "Must provide OIDC token endpoint to construct a client credentials session");
        Objects.requireNonNull(scope, "Must provide scope to construct a client credentials session");
        Objects.requireNonNull(accessToken, "Must provide an access token to construct a client credentials session");
        this.clientIdentifier = clientIdentifier;
        this.clientSecret = clientSecret;
        this.oidcProviderId = oidcProviderId;
        this.oidcTokenEndpoint = oidcTokenEndpoint;
        this.scope = scope;
        this.accessToken = accessToken;
        if (socialAgentId == null) {
            this.socialAgentId = stringToUrl("https://social.local/" + clientIdentifier);
        } else {
            this.socialAgentId = socialAgentId;
        }
        if (applicationId == null) {
            this.applicationId = stringToUrl("https://clients.local/" + clientIdentifier);
        } else {
            this.applicationId = applicationId;
        }
    }

    /**
     * Generates a map of HTTP Authorization headers that can be use to make authorized requests
     * using the session. Client credentials uses a Bearer token in a single authorization header.
     * @param method not needed - can be null for client credentials
     * @param url not needed - can be null for client credentials
     * @return Map of HTTP Authorization headers
     */
    @Override
    public Map<String, String> toHttpHeaders(HttpMethod method, URL url) {
        Objects.requireNonNull(this.accessToken, "Cannot generate authorization headers for an uninitialized access token");
        return Map.of(AUTHORIZATION.getValue(), "Bearer " + this.accessToken.getValue());
    }

    /**
     * "Refreshes" the session via another client credentials token request. A client credentials
     * flow doesn't require refresh tokens.
     * @throws SaiAuthenticationException
     */
    @Override
    public void refresh() throws SaiAuthenticationException {
        this.accessToken = obtainToken(this.clientIdentifier, this.clientSecret, this.oidcTokenEndpoint, this.scope);
    }

    /**
     * The client credentials flows don't require refresh tokens
     * @return null
     */
    @Override
    public RefreshToken getRefreshToken() { return null; }

    /**
     * POSTs a token request to the token endpoint of the oidcProvider using the provided
     * <code>clientIdentifier</code> and <code>clientSecret</code> to authenticate and request
     * the provided <code>scope</code>. Used for both initial token request and refresh (since
     * the client credentials flow doesn't require refresh tokens).
     * @param clientIdentifier client identifier that has been registered with the oidc provider
     * @param clientSecret client secret that has been registered with the oidc provider for the clientIdentifier
     * @param oidcTokenEndpoint token endpoint of the oidc provider
     * @param scope scope of access being requested
     * @return AccessToken
     * @throws SaiAuthenticationException
     */
    protected static AccessToken obtainToken(String clientIdentifier, String clientSecret, URL oidcTokenEndpoint, Scope scope) throws SaiAuthenticationException {
        Objects.requireNonNull(clientIdentifier, "Must provide a client identifier to build client credentials session");
        Objects.requireNonNull(clientSecret, "Must provide a client secret to build client credentials session");
        Objects.requireNonNull(scope, "Must provide scope to build client credentials session");
        Objects.requireNonNull(oidcTokenEndpoint, "Cannot build client credentials session without OIDC token endpoint");

        AuthorizationGrant clientGrant = new ClientCredentialsGrant();
        ClientID clientID = new ClientID(clientIdentifier);
        Secret secret = new Secret(clientSecret);
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, secret);
        TokenRequest request = new TokenRequest(urlToUri(oidcTokenEndpoint), clientAuth, clientGrant, scope);

        TokenResponse response;
        try {
            response = TokenResponse.parse(request.toHTTPRequest().send());
            if (!response.indicatesSuccess()) { throw new IOException(response.toErrorResponse().toString()); }
        } catch (IOException | ParseException ex) {
            throw new SaiAuthenticationException("Request failed to token endpoint " + oidcTokenEndpoint, ex);
        }

        AccessTokenResponse successResponse = response.toSuccessResponse();
        com.nimbusds.oauth2.sdk.token.AccessToken newToken = successResponse.getTokens().getAccessToken();
        return translateAccessToken(newToken);
    }

    /**
     * Builder for {@link ClientCredentialsSession} instances. Requires methods to be called
     * in a particular order to establish the session successfully.<br>
     * <ol>
     *     <li>{@link #setOidcProvider(URL)}</li>
     *     <li>{@link #setClientIdentifier(String)}</li>
     *     <li>{@link #setClientSecret(String)}</li>
     *     <li>{@link #setScope(List)}</li>
     *     <li>{@link #requestToken()}</li>
     *     <li>{@link #build()}</li>
     * </ol>
     */
    @NoArgsConstructor @Getter
    public static class Builder {

        private URL socialAgentId;
        private URL applicationId;
        private String clientIdentifier;
        private String clientSecret;
        private URL oidcProviderId;
        private URL oidcTokenEndpoint;
        Scope scope;
        private AccessToken accessToken;

        /**
         * Optional - Sets the social agent associated with the registered client. This is synonymous
         * with the value that the oidc provider will insert into the webid claim of the client's
         * access token.
         * @param socialAgentId URL of the social agent responsible for the application
         * @return ClientCredentialsSession.Builder
         */
        public Builder setSocialAgent(URL socialAgentId) {
            Objects.requireNonNull(socialAgentId, "Must provide a social agent id to associate with client");
            this.socialAgentId = socialAgentId;
            return this;
        }

        /**
         * Optional - Sets the application identifier associated with the registered client. 
         * @param applicationId URL of the client application identity
         * @return ClientCredentialsSession.Builder
         */
        public Builder setApplication(URL applicationId) {
            Objects.requireNonNull(applicationId, "Must provide a application id to associate with client");
            this.applicationId = applicationId;
            return this;
        }
        
        /**
         * Sets the openid connect provider that the client is registered with. Will be
         * checked for validity via .well-known/openid-configuration discovery
         * @param oidcProviderId URL of the oidc provider
         * @return ClientCredentialsSession.Builder
         */
        public Builder setOidcProvider(URL oidcProviderId) throws SaiAuthenticationException, SaiHttpException {
            Objects.requireNonNull(oidcProviderId, "Must provide an oidc provider URL to build client credentials session");
            this.oidcProviderId = oidcProviderId;
            OIDCProviderMetadata metadata = getOIDCProviderConfiguration(this.oidcProviderId);
            this.oidcTokenEndpoint = uriToUrl(metadata.getTokenEndpointURI());
            return this;
        }

        /**
         * Sets the client identifier that will be used to authenticate with the oidc provider.
         * @param clientIdentifier client identifier that has been registered with the oidc provider
         * @return ClientCredentialsSession.Builder
         */
        public Builder setClientIdentifier(String clientIdentifier) {
            Objects.requireNonNull(clientIdentifier, "Must provide a client identifier to build client credentials session");
            this.clientIdentifier = clientIdentifier;
            return this;
        }

        /**
         * Sets the client secret that will be used to authenticate with the oidc provider.
         * @param clientSecret client secret that has been registered with the oidc provider for the clientIdentifier
         * @return ClientCredentialsSession.Builder
         */
        public Builder setClientSecret(String clientSecret) {
            Objects.requireNonNull(clientSecret, "Must provide a client secret to build client credentials session");
            this.clientSecret = clientSecret;
            return this;
        }
        
        /**
         * Sets the authorization scopes to use in the authorization request
         * @param scopes List of scopes to include in request
         * @return ClientCredentialsSession.Builder
         */
        public Builder setScope(List<String> scopes) {
            Objects.requireNonNull(scopes, "Must provide scope to build client credentials session");
            String[] scopeArray = scopes.toArray(new String[0]);
            this.scope = new Scope(scopeArray);
            return this;
        }

        /**
         * Request tokens from the token endpoint of the openid connect provider
         * @return SolidOidcSession.Builder
         * @throws SaiAuthenticationException
         */
        public Builder requestToken() throws SaiAuthenticationException {
            Objects.requireNonNull(this.clientIdentifier, "Must provide a client identifier to build client credentials session");
            Objects.requireNonNull(this.clientSecret, "Must provide a client secret to build client credentials session");
            Objects.requireNonNull(this.scope, "Must provide scope to build client credentials session");
            Objects.requireNonNull(this.oidcTokenEndpoint, "Cannot request tokens without OIDC token endpoint");
            this.accessToken = obtainToken(this.clientIdentifier, this.clientSecret, this.oidcTokenEndpoint, this.scope);
            return this;
        }


        /**
         * Constructs a {@link ClientCredentialsSession} once all of the requisite operations have completed
         * successfully.
         * @return {@link ClientCredentialsSession}
         */
        public ClientCredentialsSession build() throws SaiHttpException {
            Objects.requireNonNull(this.clientIdentifier, "Must provide an OIDC client identifier to build a client credentials session");
            Objects.requireNonNull(this.clientSecret, "Must provide an OIDC client secret to build a client credentials session");
            Objects.requireNonNull(this.oidcProviderId, "Must provide an OIDC provider id to build a client credentials session");
            Objects.requireNonNull(this.oidcTokenEndpoint, "Cannot build a client credentials session without OIDC token endpoint");
            Objects.requireNonNull(this.scope, "Must provide scope to build client credentials session");
            Objects.requireNonNull(this.accessToken, "Cannot build a client credentials session without an access token");
            return new ClientCredentialsSession(this.socialAgentId, this.applicationId, this.clientIdentifier, this.clientSecret, this.oidcProviderId, this.oidcTokenEndpoint, this.scope, this.accessToken);
        }

    }

}
