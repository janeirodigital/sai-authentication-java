package com.janeirodigital.sai.authentication;

import com.janeirodigital.mockwebserver.RequestMatchingFixtureDispatcher;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.Prompt;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.commons.lang3.SerializationException;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import static com.janeirodigital.mockwebserver.DispatcherHelper.mockOnGet;
import static com.janeirodigital.mockwebserver.DispatcherHelper.mockOnPost;
import static com.janeirodigital.mockwebserver.MockWebServerHelper.toMockUri;
import static com.janeirodigital.sai.authentication.SolidOidcSession.*;
import static com.janeirodigital.sai.httputils.HttpHeader.AUTHORIZATION;
import static com.janeirodigital.sai.httputils.HttpHeader.DPOP;
import static com.janeirodigital.sai.httputils.HttpMethod.GET;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class SolidOidcSessionTests {

    private static MockWebServer server;
    private static RequestMatchingFixtureDispatcher dispatcher;
    private static OkHttpClient httpClient;
    private static URI applicationId;
    private static URI applicationMissingFieldsId;
    private static URI socialAgentId;
    private static URI socialAgentNoDpopId;
    private static URI socialAgentNoWebId;
    private static URI socialAgentNoClientId;
    private static URI socialAgentBadIoId;
    private static URI socialAgentUnknownId;
    private static URI socialAgentNoRefreshId;
    private static URI socialAgentRefreshId;
    private static URI socialAgentRefreshUnknownId;
    private static URI socialAgentRefreshNoRefreshId;
    private static URI redirect;

    private static final String redirectPath = "/projectron/redirect";
    private static final String code = "gVhyP_MCzEFUbH5ygCWYfEBAMGrLdZLwcwAPwTg0AFv";
    private static final List<String> scopes = Arrays.asList("openid", "profile", "offline_access");
    private static final Prompt prompt = new Prompt(Prompt.Type.CONSENT);


    @BeforeAll
    static void beforeAll() {
        dispatcher = new RequestMatchingFixtureDispatcher();
        // Good webid and provider configuration
        mockOnGet(dispatcher, "/alice/id", "alice-webid-ttl");
        mockOnGet(dispatcher, "/projectron/id", "projectron-application-profile-jsonld");
        mockOnGet(dispatcher, "/op/.well-known/openid-configuration", "op-configuration-json");
        mockOnPost(dispatcher, "/op/token", "op-token-response-json");
        // Application client id document missing required fields
        mockOnGet(dispatcher, "/missing-fields/projectron/id", "projectron-application-profile-missing-fields-jsonld");
        // Webid points to provider that doesn't have DPoP support
        mockOnGet(dispatcher, "/nodpop/alice/id", "alice-webid-nodpop-ttl");
        mockOnGet(dispatcher, "/nodpop/op/.well-known/openid-configuration", "op-configuration-nodpop-json");
        // Webid points to provider thaht doesn't support webid claims
        mockOnGet(dispatcher, "/nowebid/alice/id", "alice-webid-nowebid-ttl");
        mockOnGet(dispatcher, "/nowebid/op/.well-known/openid-configuration", "op-configuration-nowebid-json");
        // Webid points to provider that doesn't support client_id claims
        mockOnGet(dispatcher, "/noclientid/alice/id", "alice-webid-noclientid-ttl");
        mockOnGet(dispatcher, "/noclientid/op/.well-known/openid-configuration", "op-configuration-noclientid-json");
        // Webid points to provider with a token endpoint that gives a network IO error
        mockOnGet(dispatcher, "/badio/alice/id", "alice-webid-badio-ttl");
        mockOnGet(dispatcher, "/badio/op/.well-known/openid-configuration", "op-configuration-badio-json");
        mockOnPost(dispatcher, "/badio/op/token", "op-token-response-badio-json");
        // Webid points to provider with a token endpoint that gives an access token of unknown type
        mockOnGet(dispatcher, "/unknown/alice/id", "alice-webid-unknown-ttl");
        mockOnGet(dispatcher, "/unknown/op/.well-known/openid-configuration", "op-configuration-unknown-json");
        mockOnPost(dispatcher, "/unknown/op/token", "op-token-response-unknown-json");
        // Request is made without an offline access scope so the token endpoint doesn't give back a refresh token
        mockOnGet(dispatcher, "/norefresh/alice/id", "alice-webid-norefresh-ttl");
        mockOnGet(dispatcher, "/norefresh/op/.well-known/openid-configuration", "op-configuration-norefresh-json");
        mockOnPost(dispatcher, "/norefresh/op/token", "op-token-response-norefresh-json");
        // Request is made with an offline access scope and then a refresh is issued getting a different access token and refresh token
        mockOnGet(dispatcher, "/refresh/alice/id", "alice-webid-refresh-ttl");
        mockOnGet(dispatcher, "/refresh/op/.well-known/openid-configuration", "op-configuration-refresh-json");
        mockOnPost(dispatcher, "/refresh/op/token", "op-token-response-refresh-json");
        // Request is made with an offline access scope and then a refresh is issued getting a different access token of unknown type
        mockOnGet(dispatcher, "/refresh-unknown/alice/id", "alice-webid-refresh-unknown-ttl");
        mockOnGet(dispatcher, "/refresh-unknown/op/.well-known/openid-configuration", "op-configuration-refresh-unknown-json");
        mockOnPost(dispatcher, "/refresh-unknown/op/token", List.of("op-token-response-refresh-unknown-1-json", "op-token-response-refresh-unknown-2-json"));
        // Request is made with an offline access scope and then a refresh is issued but an additional refresh token isn't provided
        mockOnGet(dispatcher, "/refresh-norefresh/alice/id", "alice-webid-refresh-norefresh-ttl");
        mockOnGet(dispatcher, "/refresh-norefresh/op/.well-known/openid-configuration", "op-configuration-refresh-norefresh-json");
        mockOnPost(dispatcher, "/refresh-norefresh/op/token", List.of("op-token-response-refresh-norefresh-1-json", "op-token-response-refresh-norefresh-2-json"));
        
        server = new MockWebServer();
        server.setDispatcher(dispatcher);
        httpClient = new OkHttpClient.Builder().build();

        socialAgentId = toMockUri(server, "/alice/id#me");
        socialAgentNoDpopId = toMockUri(server, "/nodpop/alice/id#me");
        socialAgentNoWebId = toMockUri(server, "/nowebid/alice/id#me");
        socialAgentNoClientId = toMockUri(server, "/noclientid/alice/id#me");
        socialAgentBadIoId = toMockUri(server, "/badio/alice/id#me");
        socialAgentUnknownId = toMockUri(server, "/unknown/alice/id#me");
        socialAgentNoRefreshId = toMockUri(server, "/norefresh/alice/id#me");
        socialAgentRefreshId = toMockUri(server, "/refresh/alice/id#me");
        socialAgentRefreshUnknownId = toMockUri(server, "/refresh-unknown/alice/id#me");
        socialAgentRefreshNoRefreshId = toMockUri(server, "/refresh-norefresh/alice/id#me");

        applicationId = toMockUri(server, "/projectron/id");
        applicationMissingFieldsId = toMockUri(server, "/missing-fields/projectron/id");
        redirect = toMockUri(server, redirectPath);
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - http client")
    void initBuilderHttp() {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient);
        assertEquals(httpClient, builder.getHttpClient());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - social agent")
    void initBuilderSocialAgent() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId);
        assertEquals(socialAgentId, builder.getSocialAgentId());
        assertNotNull(builder.getOidcAuthorizationEndpoint());
        assertNotNull(builder.getOidcTokenEndpoint());
        assertNotNull(builder.getOidcProviderId());
    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - no provider dpop support")
    void failToInitBuilderNoProviderDPoP() {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient);
        assertThrows(SaiAuthenticationException.class, () -> { builder.setSocialAgent(socialAgentNoDpopId); });
    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - no provider webid claim support")
    void failToInitBuilderNoProviderWebId() {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient);
        assertThrows(SaiAuthenticationException.class, () -> { builder.setSocialAgent(socialAgentNoWebId); });
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - application - manual")
    void initBuilderApplication() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true);
        assertEquals(applicationId, builder.getApplicationId());
        assertNotNull(builder.getClientId());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - application - lookup and populate")
    void initBuilderApplicationLookup() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId);
        assertEquals(applicationId, builder.getApplicationId());
    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - application - id document missing fields")
    void failToInitBuilderApplicationMissingFields() {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient);
        assertThrows(SaiAuthenticationException.class, () -> builder.setApplication(applicationMissingFieldsId));
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - scope")
    void initBuilderScope() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes);
        for (String scope : scopes) { assertTrue(builder.getScope().contains(scope)); }
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - prompt")
    void initBuilderPrompt() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes).setPrompt(prompt);
        assertEquals(prompt, builder.getPrompt());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - redirect")
    void initBuilderRedirect() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect);
        assertTrue(builder.getRedirects().contains(redirect));
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - prepare code request")
    void initBuilderPrepareCode() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        assertNotNull(builder.getAuthorizationRequest());
        assertNotNull(builder.getRequestState());
        assertNotNull(builder.getRedirect());
        assertNotNull(builder.getCodeVerifier());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - prepare code request no prompt")
    void initBuilderPrepareCodeNoPrompt() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .addRedirect(redirect).prepareCodeRequest();
        assertNotNull(builder.getAuthorizationRequest());
        assertNotNull(builder.getCodeRequestUri());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - process code response")
    void initBuilderProcessResponse() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();

        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        builder.processCodeResponse(responseUri);
        assertNotNull(builder.getAuthorizationCode());
        assertEquals(code, builder.getAuthorizationCode().toString());
    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - state mismatch in response")
    void failToInitBuilderStateMismatch() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=ThisIsNotTheRequestState");
        assertThrows(SaiAuthenticationException.class, () -> builder.processCodeResponse(responseUri) );
    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - parse failure")
    void failToInitBuilderParseFailure() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();

        try (MockedStatic<AuthorizationResponse> mockResponse = Mockito.mockStatic(AuthorizationResponse.class)) {
            URI responseUri = toMockUri(server, redirectPath + "?codeeeeeoooooo=" + code + "&staaaattteeee=cantparsethisbro");
            mockResponse.when(() -> AuthorizationResponse.parse(any(URI.class))).thenThrow(ParseException.class);
            assertThrows(SaiAuthenticationException.class, () -> builder.processCodeResponse(responseUri));
        }

    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - misc code response failure")
    void failToInitBuilderResponseFailure() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();

        try (MockedStatic<AuthorizationResponse> mockStaticResponse = Mockito.mockStatic(AuthorizationResponse.class)) {
            AuthorizationResponse mockResponse = mock(AuthorizationResponse.class);
            AuthorizationErrorResponse mockErrorResponse = mock(AuthorizationErrorResponse.class);
            URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
            when(mockResponse.indicatesSuccess()).thenReturn(false);
            when(mockResponse.getState()).thenReturn(builder.getAuthorizationRequest().getState());
            when(mockErrorResponse.getErrorObject()).thenReturn(new ErrorObject("Problems!"));
            when(mockResponse.toErrorResponse()).thenReturn(mockErrorResponse);
            mockStaticResponse.when(() -> AuthorizationResponse.parse(any(URI.class))).thenReturn(mockResponse);
            assertThrows(SaiAuthenticationException.class, () -> builder.processCodeResponse(responseUri));
        }

    }

    @Test
    @DisplayName("Initialize solid-oidc builder - request tokens")
    void initBuilderRequestTokens() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        builder.processCodeResponse(responseUri).requestTokens();
        assertNotNull(builder.getAccessToken());
        assertNotNull(builder.getRefreshToken());
        assertNotNull(builder.getProofFactory());
    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - misc token response failure")
    void failToInitBuilderMiscTokenFailure() throws SaiAuthenticationException, ParseException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();

        try (MockedStatic<TokenResponse> mockStaticResponse = Mockito.mockStatic(TokenResponse.class)) {
            URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
            TokenResponse mockResponse = mock(TokenResponse.class);
            TokenErrorResponse mockErrorResponse = mock(TokenErrorResponse.class);
            when(mockResponse.indicatesSuccess()).thenReturn(false);
            when(mockErrorResponse.getErrorObject()).thenReturn(new ErrorObject("Problems!"));
            when(mockResponse.toErrorResponse()).thenReturn(mockErrorResponse);
            when(TokenResponse.parse(any(HTTPResponse.class))).thenReturn(mockResponse);
            builder.processCodeResponse(responseUri);
            assertThrows(SaiAuthenticationException.class, () -> builder.requestTokens());
        }

    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - token parse failure")
    void failToInitBuilderTokenParseFailure() throws SaiAuthenticationException, ParseException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();

        try (MockedStatic<TokenResponse> mockStaticResponse = Mockito.mockStatic(TokenResponse.class)) {
            URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
            when(TokenResponse.parse(any(HTTPResponse.class))).thenThrow(ParseException.class);
            builder.processCodeResponse(responseUri);
            assertThrows(SaiAuthenticationException.class, () -> builder.requestTokens());
        }

    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - token io failure")
    void failToInitBuilderTokenIOFailure() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentBadIoId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        builder.processCodeResponse(responseUri);
        assertThrows(SaiAuthenticationException.class, () -> builder.requestTokens());

    }

    @Test
    @DisplayName("Fail to initialize solid-oidc builder - unknown access token type")
    void failToInitBuilderTokenUnknown() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentUnknownId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        builder.processCodeResponse(responseUri);
        assertThrows(SaiAuthenticationException.class, () -> builder.requestTokens());

    }

    @Test
    @DisplayName("Initialize solid-oidc builder - request tokens no refresh")
    void initBuilderRequestTokensNoRefresh() throws SaiAuthenticationException {

        List<String> noRefreshScopes = Arrays.asList("openid", "profile");
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentNoRefreshId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        builder.processCodeResponse(responseUri).requestTokens();
        assertNotNull(builder.getAccessToken());
        assertNull(builder.getRefreshToken());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - build session")
    void initBuilderBuildSession() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        SolidOidcSession session = builder.processCodeResponse(responseUri).requestTokens().build();
        assertNotNull(session);
        assertEquals(socialAgentId, session.getSocialAgentId());
        assertEquals(applicationId, session.getApplicationId());
        assertNotNull(session.getOidcAuthorizationEndpoint());
        assertNotNull(session.getOidcTokenEndpoint());
        assertNotNull(session.getAccessToken());
        assertNotNull(session.getRefreshToken());
        assertNotNull(session.getProofFactory());
        assertTrue(session.toHttpHeaders(GET, redirect).containsKey(AUTHORIZATION.getValue()));
        assertTrue(session.toHttpHeaders(GET, redirect).get(AUTHORIZATION.getValue()).startsWith("DPoP"));
        assertTrue(session.toHttpHeaders(GET, redirect).containsKey(DPOP.getValue()));
        assertNotNull(session.getId("SHA-512"));
    }

    @Test
    @DisplayName("Serialize and deserialize solid-oidc session")
    void serializeAndDeserializeSession() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentId).setApplication(applicationId, true).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        SolidOidcSession session = builder.processCodeResponse(responseUri).requestTokens().build();
        byte[] serializedSession = SerializationUtils.serialize(session);
        SolidOidcSession deserialized = SerializationUtils.deserialize(serializedSession);
        assertEquals(deserialized.getSocialAgentId(), session.getSocialAgentId());
        assertEquals(deserialized.getApplicationId(), session.getApplicationId());
        assertEquals(deserialized.getAccessToken().getValue(), session.getAccessToken().getValue());
    }

    @Test
    @DisplayName("Fail to deserialize solid-oidc session - dpop failure")
    void failToDeserializeDPoP() {
        SolidOidcSession mockSession = mock(SolidOidcSession.class, withSettings().serializable());
        ECKey mockEcKey = mock(ECKey.class);
        when(mockEcKey.isPrivate()).thenReturn(false);
        when(mockSession.getEcJwk()).thenReturn(mockEcKey);
        byte[] serializedSession = SerializationUtils.serialize(mockSession);
        assertThrows(SerializationException.class, () -> SerializationUtils.deserialize(serializedSession));
    }

    @Test
    @DisplayName("Refresh solid-oidc session")
    void initBuilderRefreshSession() throws SaiAuthenticationException {

        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentRefreshId).setApplication(applicationId).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        SolidOidcSession session = builder.processCodeResponse(responseUri).requestTokens().build();
        assertNotNull(session);
        AccessToken originalAccessToken = session.getAccessToken();
        RefreshToken originalRefreshToken = session.getRefreshToken();
        session.refresh();
        assertNotEquals(originalAccessToken, session.getAccessToken());
        assertNotEquals(originalRefreshToken, session.getRefreshToken());
    }

    @Test
    @DisplayName("Fail to refresh session - no refresh token")
    void failToRefreshSessionNullRefresh() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentNoRefreshId).setApplication(applicationId).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        SolidOidcSession session = builder.processCodeResponse(responseUri).requestTokens().build();
        assertThrows(SaiAuthenticationException.class, () -> session.refresh());
    }

    @Test
    @DisplayName("Fail to refresh session - unknown token type returned")
    void failToRefreshSessionUnknownToken() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentRefreshUnknownId).setApplication(applicationId).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        SolidOidcSession session = builder.processCodeResponse(responseUri).requestTokens().build();
        assertThrows(SaiAuthenticationException.class, () -> session.refresh());
    }

    @Test
    @DisplayName("Refresh session - no refresh token returned")
    void failToRefreshSessionNoRefresh() throws SaiAuthenticationException {
        SolidOidcSession.Builder builder = new SolidOidcSession.Builder();
        builder.setHttpClient(httpClient).setSocialAgent(socialAgentRefreshNoRefreshId).setApplication(applicationId).setScope(scopes)
                .setPrompt(prompt).addRedirect(redirect).prepareCodeRequest();
        URI responseUri = toMockUri(server, redirectPath + "?code=" + code + "&state=" + builder.getAuthorizationRequest().getState());
        SolidOidcSession session = builder.processCodeResponse(responseUri).requestTokens().build();
        assertNotNull(session);
        session.refresh();
        assertNotNull(session.getAccessToken());
        assertNull(session.getRefreshToken());
    }

    @Test
    @DisplayName("Fail to get elliptic curve key - invalid curve")
    void failToGetEcKey() {
        assertThrows(SaiAuthenticationException.class, () -> getEllipticCurveKey(new Curve("NOTREAL")));
    }

    @Test
    @DisplayName("Fail to get dpop factory - invalid key")
    void failToGetProofFactory() {
        ECKey mockEcKey = mock(ECKey.class);
        when(mockEcKey.isPrivate()).thenReturn(false);
        assertThrows(SaiAuthenticationException.class, () -> getDPoPProofFactory(mockEcKey));
    }

    @Test
    @DisplayName("Fail to get proof - jose error")
    void failToGetDpopProofJose() throws JOSEException {
        DefaultDPoPProofFactory mockProofFactory = mock(DefaultDPoPProofFactory.class);
        when(mockProofFactory.createDPoPJWT(anyString(), any(URI.class))).thenThrow(JOSEException.class);
        assertThrows(SaiAuthenticationException.class, () -> getProof(mockProofFactory, GET, redirect));
    }



}
