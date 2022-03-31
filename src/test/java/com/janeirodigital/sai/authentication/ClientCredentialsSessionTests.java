package com.janeirodigital.sai.authentication;

import com.janeirodigital.mockwebserver.RequestMatchingFixtureDispatcher;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.BeforeEach;
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
import static com.janeirodigital.sai.httputils.HttpHeader.AUTHORIZATION;
import static com.janeirodigital.sai.httputils.HttpMethod.GET;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientCredentialsSessionTests {

    private static MockWebServer server;
    private static RequestMatchingFixtureDispatcher dispatcher;
    private static URI oidcProviderId;
    private static URI socialAgentId;
    private static URI applicationId;
    private static final String clientIdentifier = "sai-java-client";
    private static final String clientSecret = "AAaabbBB-client-java-sai-BBbbaaAA";
    private static final List<String> scopes = Arrays.asList("openid", "profile");

    @BeforeEach
    void beforeEach() {
        dispatcher = new RequestMatchingFixtureDispatcher();
        server = new MockWebServer();
        server.setDispatcher(dispatcher);
        // Regular client authentication
        mockOnGet(dispatcher, "/cc/op/.well-known/openid-configuration", "op-configuration-cc-json");
        mockOnPost(dispatcher, "/cc/op/token", List.of("op-token-response-cc-json"));

        oidcProviderId = toMockUri(server, "/cc/op/");

        socialAgentId = URI.create("https://acme.example/id#org");
        applicationId = URI.create("https://projectron.example/id#app");
    }

    @Test
    @DisplayName("Initialize client credentials builder - social agent")
    void initBuilderSocialAgent() {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setSocialAgent(socialAgentId);
        assertEquals(socialAgentId, builder.getSocialAgentId());
    }

    @Test
    @DisplayName("Initialize client credentials builder - application")
    void initBuilderApplication() {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setApplication(applicationId);
        assertEquals(applicationId, builder.getApplicationId());
    }

    @Test
    @DisplayName("Initialize client credentials builder - oidc provider")
    void initBuilderOidcProvider() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setOidcProvider(oidcProviderId);
        assertEquals(oidcProviderId, builder.getOidcProviderId());
        assertNotNull(builder.getOidcTokenEndpoint());
    }

    @Test
    @DisplayName("Initialize client credentials builder - client identifier")
    void initBuilderClientIdentifier() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setOidcProvider(oidcProviderId).setClientIdentifier(clientIdentifier);
        assertEquals(clientIdentifier, builder.getClientIdentifier());
    }

    @Test
    @DisplayName("Initialize client credentials builder - client secret")
    void initBuilderClientSecret() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setOidcProvider(oidcProviderId).setClientIdentifier(clientIdentifier).setClientSecret(clientSecret);
        assertEquals(clientSecret, builder.getClientSecret());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - scope")
    void initBuilderScope() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setOidcProvider(oidcProviderId).setClientIdentifier(clientIdentifier).setClientSecret(clientSecret).setScope(scopes);
        for (String scope : scopes) { assertTrue(builder.getScope().contains(scope)); }
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - request tokens")
    void initBuilderRequestTokens() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setOidcProvider(oidcProviderId).setClientIdentifier(clientIdentifier).setClientSecret(clientSecret)
                .setScope(scopes).requestToken();
        assertNotNull(builder.getAccessToken());
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - misc token response failure")
    void initBuilderRequestTokensResponseFailure() throws SaiAuthenticationException, ParseException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        builder.setOidcProvider(oidcProviderId).setClientIdentifier(clientIdentifier).setClientSecret(clientSecret).setScope(scopes);
        try (MockedStatic<TokenResponse> mockStaticResponse = Mockito.mockStatic(TokenResponse.class)) {
            TokenResponse mockResponse = mock(TokenResponse.class);
            TokenErrorResponse mockErrorResponse = mock(TokenErrorResponse.class);
            when(mockResponse.indicatesSuccess()).thenReturn(false);
            when(mockErrorResponse.getErrorObject()).thenReturn(new ErrorObject("Problems!"));
            when(mockResponse.toErrorResponse()).thenReturn(mockErrorResponse);
            when(TokenResponse.parse(any(HTTPResponse.class))).thenReturn(mockResponse);
            assertThrows(SaiAuthenticationException.class, () -> builder.requestToken());
        }
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - build session")
    void initBuilderBuildSession() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        ClientCredentialsSession session = builder.setSocialAgent(socialAgentId)
                                                  .setApplication(applicationId)
                                                  .setOidcProvider(oidcProviderId)
                                                  .setClientIdentifier(clientIdentifier)
                                                  .setClientSecret(clientSecret)
                                                  .setScope(scopes)
                                                  .requestToken()
                                                  .build();
        assertNotNull(session);
        assertEquals(oidcProviderId, session.getOidcProviderId());
        assertNotNull(session.getOidcTokenEndpoint());
        assertEquals(clientIdentifier, session.getClientIdentifier());
        assertEquals(clientSecret, session.getClientSecret());
        assertEquals(session.getAccessToken(), builder.getAccessToken());
        assertTrue(session.toHttpHeaders(GET, oidcProviderId).containsKey(AUTHORIZATION.getValue()));
        assertTrue(session.toHttpHeaders(GET, oidcProviderId).get(AUTHORIZATION.getValue()).startsWith("Bearer"));
        assertNotNull(session.getScope());
        assertNull(session.getRefreshToken());
        assertEquals(socialAgentId, session.getSocialAgentId());
        assertEquals(applicationId, session.getApplicationId());
        assertNotNull(session.getId("SHA-512"));
    }

    @Test
    @DisplayName("Initialize solid-oidc builder - build session - no identifiers")
    void initBuilderBuildSessionNoIds() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        ClientCredentialsSession session = builder.setOidcProvider(oidcProviderId)
                                                  .setClientIdentifier(clientIdentifier)
                                                  .setClientSecret(clientSecret)
                                                  .setScope(scopes)
                                                  .requestToken()
                                                  .build();
        assertNotNull(session);
        assertEquals("https://social.local/" + builder.getClientIdentifier(), session.getSocialAgentId().toString());
        assertEquals("https://clients.local/" + builder.getClientIdentifier(), session.getApplicationId().toString());
        assertNotNull(session.getId("SHA-512"));
    }

    @Test
    @DisplayName("Refresh client credentials session")
    void refreshSession() throws SaiAuthenticationException {
        ClientCredentialsSession.Builder builder = new ClientCredentialsSession.Builder();
        ClientCredentialsSession session = builder.setOidcProvider(oidcProviderId)
                .setClientIdentifier(clientIdentifier)
                .setClientSecret(clientSecret)
                .setScope(scopes)
                .requestToken()
                .build();
        assertNotNull(session);
        AccessToken original = session.getAccessToken();
        session.refresh();
        assertNotEquals(original, session.getAccessToken());
    }
}
