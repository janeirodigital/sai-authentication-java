package com.janeirodigital.sai.authentication;

import com.janeirodigital.sai.httputils.HttpMethod;
import com.janeirodigital.sai.httputils.SaiHttpException;
import com.janeirodigital.sai.rdfutils.RdfUtils;
import com.janeirodigital.sai.rdfutils.SaiRdfException;
import com.janeirodigital.sai.rdfutils.SaiRdfNotFoundException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.Getter;
import lombok.NoArgsConstructor;
import okhttp3.OkHttpClient;
import org.apache.jena.rdf.model.Resource;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URL;
import java.util.*;

import static com.janeirodigital.sai.authentication.AuthorizedSessionHelper.*;
import static com.janeirodigital.sai.authentication.SolidOidcVocabulary.SOLID_OIDC_REDIRECT_URIS;
import static com.janeirodigital.sai.authentication.SolidOidcVocabulary.SOLID_OIDC_SCOPE;
import static com.janeirodigital.sai.httputils.HttpHeader.AUTHORIZATION;
import static com.janeirodigital.sai.httputils.HttpHeader.DPOP;
import static com.janeirodigital.sai.httputils.HttpMethod.POST;
import static com.janeirodigital.sai.httputils.HttpUtils.uriToUrl;
import static com.janeirodigital.sai.httputils.HttpUtils.urlToUri;
import static com.janeirodigital.sai.rdfutils.RdfUtils.getRequiredStringObject;

/**
 * Implementation of {@link AuthorizedSession} for
 * <a href="https://solid.github.io/solid-oidc/">Solid-OIDC</a>. Must use
 * {@link Builder} for session creation.
 */
@Getter
public class SolidOidcSession implements AuthorizedSession {

    private final URL socialAgentId;
    private final URL applicationId;
    private final URL oidcProviderId;
    private final URL oidcTokenEndpoint;
    private final URL oidcAuthorizationEndpoint;
    private AccessToken accessToken;
    private RefreshToken refreshToken;
    private final ECKey ecJwk;
    private transient DPoPProofFactory proofFactory;

    protected SolidOidcSession(URL socialAgentId, URL applicationId, URL oidcProviderId, URL oidcAuthorizationEndpoint,
                               URL oidcTokenEndpoint, AccessToken accessToken, RefreshToken refreshToken, ECKey ecJwk, DPoPProofFactory proofFactory) {
        Objects.requireNonNull(socialAgentId, "Must provide a Social Agent identifier to construct a Solid OIDC session");
        Objects.requireNonNull(applicationId, "Must provide an application identifier to construct a Solid OIDC session");
        Objects.requireNonNull(oidcProviderId, "Must provide an OIDC provider identifier to construct a Solid OIDC session");
        Objects.requireNonNull(oidcAuthorizationEndpoint, "Must provide OIDC authorization endpoint to construct a Solid OIDC session");
        Objects.requireNonNull(oidcTokenEndpoint, "Must provide OIDC token endpoint to construct a Solid OIDC session");
        Objects.requireNonNull(accessToken, "Must provide an access token to construct a Solid OIDC session");
        Objects.requireNonNull(ecJwk, "Must provide an elliptic curve key to construct a Solid OIDC session");
        Objects.requireNonNull(proofFactory, "Must provide a DPoP proof factory to construct a Solid OIDC session");
        this.socialAgentId = socialAgentId;
        this.applicationId = applicationId;
        this.oidcProviderId = oidcProviderId;
        this.oidcAuthorizationEndpoint = oidcAuthorizationEndpoint;
        this.oidcTokenEndpoint = oidcTokenEndpoint;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.ecJwk = ecJwk;
        this.proofFactory = proofFactory;
    }

    /**
     * Generates a map of HTTP Authorization headers that can be use to make authorized requests
     * using the session. DPoP requires a proof to be created for each request based on the
     * <code>method</code> and target <code>url</code>.
     * @param method HTTP method of the request
     * @param url Target URL of the request
     * @return Map of HTTP Authorization headers
     * @throws SaiAuthenticationException
     */
    @Override
    public Map<String, String> toHttpHeaders(HttpMethod method, URL url) throws SaiAuthenticationException {
        Objects.requireNonNull(method, "Must provide the HTTP method of the request to generate headers for");
        Objects.requireNonNull(url, "Must provide the target URL of the request to generate headers for");
        Objects.requireNonNull(this.accessToken, "Cannot generate authorization headers for an uninitialized access token");
        SignedJWT proof = getProof(this.proofFactory, method, url);
        return Map.of(AUTHORIZATION.getValue(), "DPoP " + this.accessToken.getValue(), DPOP.getValue(), proof.serialize());
    }

    /**
     * Refreshes the tokens associated with the session. Session must have been established as
     * refreshable upon creation.
     * @throws SaiAuthenticationException
     */
    @Override
    public void refresh() throws SaiAuthenticationException {
        Objects.requireNonNull(this.applicationId, "Must provide an application identifier to use as client id in session refresh");
        Objects.requireNonNull(this.oidcTokenEndpoint, "Must provide openid token endpoint for session refresh");
        Objects.requireNonNull(this.proofFactory, "Must provide a dpop proof factory for session refresh");
        if (this.refreshToken == null) { throw new SaiAuthenticationException("Unable to refresh a session without a refresh token"); }
        // Construct the grant from the saved refresh token
        com.nimbusds.oauth2.sdk.token.RefreshToken nimbusRefreshToken = new com.nimbusds.oauth2.sdk.token.RefreshToken(this.refreshToken.getValue());
        AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(nimbusRefreshToken);
        ClientID clientId = new ClientID(this.applicationId.toString());
        Tokens tokens = obtainTokens(this.oidcTokenEndpoint, clientId, refreshTokenGrant, this.proofFactory);
        if (tokens.getDPoPAccessToken() == null) { throw new SaiAuthenticationException("Access token is not DPoP"); }
        this.accessToken = translateAccessToken(tokens.getDPoPAccessToken());
        if (tokens.getRefreshToken() != null) {
            this.refreshToken = translateRefreshToken(tokens.getRefreshToken());
        } else {
            this.refreshToken = null;
        }
    }

    /**
     * Gets the required DPoP proof that must be created for each request based on the
     * <code>method</code> and target <code>url</code>.
     * @param proofFactory DPoP proof factory
     * @param method HTTP method of the request
     * @param url Target URL of the request
     * @return DPoP proof
     * @throws SaiAuthenticationException
     */
    protected static SignedJWT getProof(DPoPProofFactory proofFactory, HttpMethod method, URL url) throws SaiAuthenticationException {
        Objects.requireNonNull(proofFactory, "Must provide a DPoP proof factory to get DPoP proof");
        Objects.requireNonNull(method, "Must provide the HTTP method of the request to generate DPoP proof");
        Objects.requireNonNull(url, "Must provide the target URL of the request to generate DPoP proof");
        try {
            return proofFactory.createDPoPJWT(method.getValue(), urlToUri(url));
        } catch (JOSEException ex) {
            throw new SaiAuthenticationException("Unable to create DPoP proof", ex);
        }
    }

    protected static ECKey getEllipticCurveKey(Curve curve) throws SaiAuthenticationException {
        try { return new ECKeyGenerator(curve).keyID("1").generate(); } catch (JOSEException ex) {
            throw new SaiAuthenticationException("Failed to generate elliptic curve key", ex);
        }
    }

    /**
     * Gets a DPoP proof factory that can be used for generate DPoP proofs for requests
     * made by the session.
     * @param ecJwk Elliptic Curve JWK
     * @return DPoPProofFactory
     * @throws SaiAuthenticationException
     */
    protected static DPoPProofFactory getDPoPProofFactory(ECKey ecJwk) throws SaiAuthenticationException {
        try {
            return new DefaultDPoPProofFactory(ecJwk, JWSAlgorithm.ES256);
        } catch (Exception ex) {
            throw new SaiAuthenticationException("Failed to initiate DPoP proof generation infrastructure", ex);
        }
    }

    /**
     * Post a token request to the token endpoint provided in <code>oidcProviderMetadata</code>. Used in
     * both the initial token request as well as in subsequent token refreshes.
     * @param oidcTokenEndpoint URL of the oidc token endpoint
     * @param clientId client identifier
     * @param grant authorization grant
     * @param proofFactory DPoP proof factory
     * @return Tokens object containing requested tokens
     * @throws SaiAuthenticationException
     */
    protected static Tokens obtainTokens(URL oidcTokenEndpoint, ClientID clientId, AuthorizationGrant grant, DPoPProofFactory proofFactory) throws SaiAuthenticationException {
        TokenRequest request;
        request = new TokenRequest(urlToUri(oidcTokenEndpoint), clientId, grant);
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setAccept("*/*");
        SignedJWT proof = getProof(proofFactory, POST, httpRequest.getURL());
        httpRequest.setDPoP(proof);
        TokenResponse response;
        try {
            response = TokenResponse.parse(httpRequest.send());
            if (!response.indicatesSuccess()) { throw new SaiAuthenticationException(response.toErrorResponse().toString()); }
        } catch (IOException | ParseException ex) {
            throw new SaiAuthenticationException("Request failed to token endpoint " + oidcTokenEndpoint, ex);
        }
        return response.toSuccessResponse().getTokens();
    }

    private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
        ois.defaultReadObject();
        try { this.proofFactory = getDPoPProofFactory(this.getEcJwk()); } catch (SaiAuthenticationException ex) {
            throw new IOException("Failed to deserialize DPoP proof factory", ex);
        }
    }

    /**
     * Builder for {@link SolidOidcSession} instances. Requires methods to be called
     * in a particular order to establish the Solid-OIDC session successfully.<br>
     * <ol>
     *     <li>{@link #setHttpClient(OkHttpClient)}</li>
     *     <li>{@link #setSocialAgent(URL)}</li>
     *     <li>{@link #setApplication(URL)}</li>
     *     <li>{@link #setScope(List)}</li>
     *     <li>{@link #setPrompt(Prompt)}</li>
     *     <li>{@link #addRedirect(URL)}</li>
     *     <li>{@link #prepareCodeRequest()}</li>
     *     <li>{@link #getCodeRequestUrl()}</li>
     *     <li>{@link #processCodeResponse(URL)}</li>
     *     <li>{@link #requestTokens()}</li>
     *     <li>{@link #build()}</li>
     * </ol>
     */
    @NoArgsConstructor @Getter
    public static class Builder {

        private URL socialAgentId;
        private URL applicationId;
        private ClientID clientId;
        private URL oidcProviderId;
        private URL oidcAuthorizationEndpoint;
        private URL oidcTokenEndpoint;
        private OkHttpClient httpClient;
        private Scope scope;
        private Prompt prompt;
        private State requestState;
        private List<URL> redirects;
        private URL redirect;
        private CodeVerifier codeVerifier;
        private AuthorizationRequest authorizationRequest;
        private AuthorizationCode authorizationCode;
        private ECKey ecJwk;
        private DPoPProofFactory proofFactory;
        private AccessToken accessToken;
        private RefreshToken refreshToken;

        /**
         * Sets an http client that can be used for various operations when building a Solid OIDC session
         * @param httpClient HTTP client to use for requests
         * @return SolidOidcSession.Builder
         */
        public Builder setHttpClient(OkHttpClient httpClient) {
            Objects.requireNonNull(httpClient, "Must provide an http client to build a Solid OIDC session");
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Sets the Social Agent that the Solid-OIDC session will be established on behalf of.
         * Looks up the provided <code>socialAgentId</code> and gets an OIDC Issuer(s) trusted
         * by the social agent, then ensures the issuer has a compatible configuration and stores
         * pertinent information about it.
         * @param socialAgentId URL of the SocialAgent Identity
         * @return SolidOidcSession.Builder
         */
        public Builder setSocialAgent(URL socialAgentId) throws SaiAuthenticationException, SaiHttpException {
            Objects.requireNonNull(this.httpClient, "Must provide an http client to build a Solid OIDC session");
            Objects.requireNonNull(socialAgentId, "Must provide a Social Agent identifier to build a Solid OIDC session");
            this.socialAgentId = socialAgentId;
            this.oidcProviderId = getOidcIssuerForSocialAgent(this.httpClient, this.socialAgentId);
            OIDCProviderMetadata metadata = getOIDCProviderConfiguration(this.oidcProviderId);
            // Ensure that the OIDC Provider supports DPoP
            if (metadata.getDPoPJWSAlgs() == null) {
                throw new SaiAuthenticationException("OpenID Provider " + this.oidcProviderId.toString() + "does not support DPoP");
            }
            // Ensure that the OIDC Provider can issue webid and client_id claims
            if (!metadata.getClaims().contains("webid") || !metadata.getClaims().contains("client_id")) {
                throw new SaiAuthenticationException("OpenID Provider " + this.oidcProviderId.toString() + "does not support the necessary claims for solid-oidc");
            }
            this.oidcAuthorizationEndpoint = uriToUrl(metadata.getAuthorizationEndpointURI());
            this.oidcTokenEndpoint = uriToUrl(metadata.getTokenEndpointURI());
            return this;
        }

        /**
         * Sets the client Application that will use the Solid-OIDC session. Looks up the provided
         * <code>applicationId</code> to ensure it is available and well-formed.
         * @param applicationId URL of the Client Application Identity
         * @return SolidOidcSession.Builder
         */
        public Builder setApplication(URL applicationId) throws SaiAuthenticationException {
            return setApplication(applicationId, false);
        }

        /**
         * Sets the client application identifier for the Solid-OIDC session, with the ability
         * to lookup the client document and extract additional criteria (redirect uris and scope) for
         * the session automatically (which can be disabled by setting <code>manual</code> to false).
         * @param applicationId URL of the Client Application Identity
         * @param manual When true, do not populate and session criteria automatically from client id document
         * @return SolidOidcSession.Builder
         * @throws SaiAuthenticationException
         */
        public Builder setApplication(URL applicationId, boolean manual) throws SaiAuthenticationException {
            Objects.requireNonNull(applicationId, "Must provide an application identifier to build a Solid OIDC session");
            Objects.requireNonNull(httpClient, "Must provide an http client to build a Solid OIDC session");
            if (!manual) {
                Resource clientDocument = getClientIdDocument(this.httpClient, applicationId);
                try {
                    this.setRedirects(RdfUtils.getRequiredUrlObjects(clientDocument, SOLID_OIDC_REDIRECT_URIS));
                    this.setScope(Arrays.asList(getRequiredStringObject(clientDocument, SOLID_OIDC_SCOPE).split(" ")));
                } catch (SaiRdfNotFoundException | SaiRdfException ex) {
                    throw new SaiAuthenticationException("Unable to set application. Required attributes missing from client id document", ex);
                }
            }
            this.applicationId = applicationId;
            this.clientId = new ClientID(this.applicationId.toString());
            return this;
        }

        /**
         * Sets the authorization scopes to use in the authorization request
         * @param scopes List of scopes to include in request
         * @return SolidOidcSession.Builder
         */
        public Builder setScope(List<String> scopes) {
            Objects.requireNonNull(scopes, "Must provide scopes to set authorization request scope");
            String[] scopeArray = scopes.toArray(new String[0]);
            this.scope = new Scope(scopeArray);
            return this;
        }

        /**
         * Sets the prompt to use in the authorization request
         * @param prompt prompt to use in the authorization request
         * @return SolidOidcSession.Builder
         */
        public Builder setPrompt(Prompt prompt) {
            Objects.requireNonNull(prompt, "Must provide prompt to set prompt for authorization request");
            this.prompt = prompt;
            return this;
        }

        /**
         * Adds a redirect URI to use in the authorization request
         * @param redirect redirection URI to use in the authorization request
         * @return SolidOidcSession.Builder
         */
        public Builder addRedirect(URL redirect) {
            Objects.requireNonNull(redirect, "Must provide redirection endpoint for authorization request");
            if (this.redirects == null) { this.redirects = new ArrayList<>(); }
            this.redirects.add(redirect);
            return this;
        }

        /**
         * Sets the list of redirect URIs to use in the authorization request
         * @param redirects redirection URIs to use in the authorization request
         * @return SolidOidcSession.Builder
         */
        public Builder setRedirects(List<URL> redirects) {
            Objects.requireNonNull(redirects, "Must provide redirection endpoints for authorization request");
            this.redirects = redirects;
            return this;
        }

        /**
         * Prepares an Authorization Code Request which should be provided to the Social Agent for review in-browser
         * @return SolidOidcSession.Builder
         */
        public Builder prepareCodeRequest() {
            Objects.requireNonNull(this.clientId, "Must provide a client application for the authorization request");
            Objects.requireNonNull(this.redirects, "Must provide one or more redirects for the authorization request");
            Objects.requireNonNull(this.scope, "Must provide a scope for the authorization request");
            Objects.requireNonNull(this.oidcAuthorizationEndpoint, "Cannot prepare authorization request without OIDC authorization endpoint");
            this.requestState = new State();
            this.codeVerifier = new CodeVerifier();  // Generate a new random 256 bit code verifier for PKCE
            if (this.redirects.size() == 1) { this.redirect = this.redirects.get(0); } else {
                // Pick a redirect to use at random
                Random random = new Random();
                this.redirect = this.redirects.get(random.nextInt(this.redirects.size()));
            }
            AuthorizationRequest.Builder requestBuilder = new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), this.clientId);
            requestBuilder.scope(scope)
                          .state(this.requestState)
                          .codeChallenge(this.codeVerifier, CodeChallengeMethod.S256)
                          .redirectionURI(urlToUri(this.redirect))
                          .endpointURI(urlToUri(this.oidcAuthorizationEndpoint));
            if (this.prompt != null) { requestBuilder.prompt(this.prompt); }
            this.authorizationRequest = requestBuilder.build();
            return this;
        }

        /**
         * Returns the prepared authorization code request URL
         * @return URL of the generated authorization code request
         */
        public URL getCodeRequestUrl() throws SaiHttpException {
            Objects.requireNonNull(this.authorizationRequest, "Cannot get code request URL before the code request is prepared");
            return uriToUrl(this.authorizationRequest.toURI());
        }

        /**
         * Process the response to the authorization code request. All of the information
         * needed is fully contained in the URL of the response.
         * @param redirectResponse URL response to the authorization code request
         * @return SolidOidcSession.Builder
         * @throws SaiAuthenticationException
         */
        public Builder processCodeResponse(URL redirectResponse) throws SaiAuthenticationException {
            Objects.requireNonNull(redirectResponse, "Must provide a response to process authorization code response");
            Objects.requireNonNull(this.requestState, "Must provide an original request state to process a valid code response");
            AuthorizationResponse response;
            try {
                // Parse the authorization response from the callback URI
                response = AuthorizationResponse.parse(urlToUri(redirectResponse));
            } catch (ParseException ex) {
                throw new SaiAuthenticationException("Failed to parse response to authorization code request: " + ex.getMessage());
            }
            // Check that the returned state parameter matches the original
            if (!this.requestState.equals(response.getState())) {
                throw new SaiAuthenticationException("Unexpected or tampered contents detected in authorization response");
            }
            if (!response.indicatesSuccess()) {
                // The request was denied or some error occurred
                AuthorizationErrorResponse errorResponse = response.toErrorResponse();
                throw new SaiAuthenticationException("Authorization requested failed: " + errorResponse.getErrorObject());
            }
            AuthorizationSuccessResponse successResponse = response.toSuccessResponse();
            // Retrieve the authorisation code, to be used later to exchange the code for
            // an access token at the token endpoint of the server
            this.authorizationCode = successResponse.getAuthorizationCode();
            return this;
        }

        /**
         * Request tokens from the token endpoint of the openid connect provider
         * @return SolidOidcSession.Builder
         * @throws SaiAuthenticationException
         */
        public Builder requestTokens() throws SaiAuthenticationException {
            Objects.requireNonNull(this.clientId, "Must provide a client application for the token request");
            Objects.requireNonNull(this.oidcTokenEndpoint, "Cannot request tokens without OIDC token endpoint");
            Objects.requireNonNull(this.authorizationCode, "Cannot request tokens without authorization code");
            Objects.requireNonNull(this.redirects, "Must provide a redirect for the token request");
            Objects.requireNonNull(this.codeVerifier, "Must provide a code verifier for the token request");
            this.ecJwk = getEllipticCurveKey(Curve.P_256);
            this.proofFactory = getDPoPProofFactory(this.getEcJwk());
            Tokens tokens = obtainTokens(this.oidcTokenEndpoint, this.clientId, new AuthorizationCodeGrant(this.authorizationCode, urlToUri(this.redirect), this.codeVerifier), this.proofFactory);
            // The access token is not of type DPoP
            if (tokens.getDPoPAccessToken() == null) { throw new SaiAuthenticationException("Access token is not DPoP"); }
            this.accessToken = translateAccessToken(tokens.getDPoPAccessToken());
            if (tokens.getRefreshToken() != null) { this.refreshToken = translateRefreshToken(tokens.getRefreshToken()); }
            return this;
        }

        /**
         * Constructs a {@link SolidOidcSession} once all of the requisite operations have completed
         * successfully.
         * @return {@link SolidOidcSession}
         */
        public SolidOidcSession build() {
            Objects.requireNonNull(this.socialAgentId, "Must provide a Social Agent identifier to build a Solid OIDC session");
            Objects.requireNonNull(this.applicationId, "Must provide an application identifier to build a Solid OIDC session");
            Objects.requireNonNull(this.oidcProviderId, "Must provide an OIDC provider id to build a Solid OIDC session");
            Objects.requireNonNull(this.oidcAuthorizationEndpoint, "Cannot build a Solid OIDC session without OIDC authorization endpoint");
            Objects.requireNonNull(this.oidcTokenEndpoint, "Cannot build a Solid OIDC session without OIDC token endpoint");
            Objects.requireNonNull(this.accessToken, "Cannot build a Solid OIDC session without an access token");
            Objects.requireNonNull(this.ecJwk, "Cannot build a Solid OIDC session without an elliptic curve key");
            Objects.requireNonNull(this.proofFactory, "Cannot build a Solid OIDC session without a proof factory");
            return new SolidOidcSession(this.socialAgentId, this.applicationId, this.oidcProviderId, this.oidcAuthorizationEndpoint, this.oidcTokenEndpoint, this.accessToken, this.refreshToken, this.ecJwk, this.proofFactory);
        }

    }

}
