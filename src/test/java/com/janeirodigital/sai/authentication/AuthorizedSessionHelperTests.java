package com.janeirodigital.sai.authentication;

import com.janeirodigital.mockwebserver.RequestMatchingFixtureDispatcher;
import com.janeirodigital.sai.httputils.ContentType;
import com.janeirodigital.sai.httputils.HttpHeader;
import com.janeirodigital.sai.httputils.HttpMethod;
import com.janeirodigital.sai.httputils.SaiHttpException;
import com.janeirodigital.sai.rdfutils.SaiRdfException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static com.janeirodigital.mockwebserver.DispatcherHelper.*;
import static com.janeirodigital.mockwebserver.MockWebServerHelper.toMockUri;
import static com.janeirodigital.sai.authentication.AuthorizedSessionHelper.*;
import static com.janeirodigital.sai.authentication.SolidOidcVocabulary.SOLID_OIDC_CLIENT_NAME;
import static com.janeirodigital.sai.authentication.SolidOidcVocabulary.SOLID_OIDC_DEFAULT_MAX_AGE;
import static com.janeirodigital.sai.httputils.ContentType.TEXT_TURTLE;
import static com.janeirodigital.sai.httputils.HttpHeader.IF_NONE_MATCH;
import static com.janeirodigital.sai.httputils.HttpMethod.GET;
import static com.janeirodigital.sai.httputils.HttpUtils.setHttpHeader;
import static com.janeirodigital.sai.httputils.HttpUtils.uriToUrl;
import static com.janeirodigital.sai.rdfutils.RdfUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizedSessionHelperTests {

    private static MockWebServer server;
    private static RequestMatchingFixtureDispatcher dispatcher;
    private static OkHttpClient httpClient;
    private static URI socialAgentId;
    private static URI clientId;
    private static URI oidcProviderId;
    private static final String TOKEN_VALUE = "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3";

    @BeforeAll
    static void beforeAll() {
        // Initialize request fixtures for the MockWebServer
        dispatcher = new RequestMatchingFixtureDispatcher();
        // Good op configuration and webid pointing to that issuer
        mockOnGet(dispatcher, "/op/.well-known/openid-configuration", "op-configuration-json");
        mockOnGet(dispatcher, "/alice/id", "alice-webid-ttl");
        // Op configuration with mismatch on issuer
        mockOnGet(dispatcher, "/mismatch/.well-known/openid-configuration", "op-configuration-json");
        // In a given test, the first request to this endpoint will return provider-response, the second will return provider-refresh (a different token)
        mockOnPost(dispatcher, "/op/token", List.of("token-provider-response-json", "token-provider-refresh-json"));
        // Good client identity document for projectron
        mockOnGet(dispatcher, "/projectron", "projectron-clientid-jsonld");
        // Protected text document
        mockOnGet(dispatcher, "/protected", "protected-txt");
        mockOnPut(dispatcher, "/protected", "204");
        mockOnDelete(dispatcher, "/protected", "204");
        // Protected Turtle document
        mockOnGet(dispatcher, "/ttl/protected", "protected-ttl");
        mockOnPut(dispatcher, "/ttl/protected", "204");
        // Protected JSON-LD document
        mockOnGet(dispatcher, "/jsonld/protected", "protected-jsonld");
        mockOnPut(dispatcher, "/jsonld/protected", "204");
        // Initialize the Mock Web Server and assign the initialized dispatcher
        server = new MockWebServer();
        server.setDispatcher(dispatcher);

        httpClient = new OkHttpClient.Builder().build();

        clientId = toMockUri(server, "/projectron");
        socialAgentId = toMockUri(server, "/alice/id#me");
        oidcProviderId = toMockUri(server, "/op/");

    }

    @Test
    @DisplayName("Get oidc provider configuration")
    void getConfigurationForOIDCProvider() throws SaiAuthenticationException {
        OIDCProviderMetadata oidcProvider = getOIDCProviderConfiguration(toMockUri(server, "/op/"));
        assertEquals(toMockUri(server,"/op/token"), oidcProvider.getTokenEndpointURI());
        assertEquals(toMockUri(server,"/op/auth"), oidcProvider.getAuthorizationEndpointURI());
        assertEquals(toMockUri(server,"/op/reg"), oidcProvider.getRegistrationEndpointURI());
    }

    @Test
    @DisplayName("Fail to get oidc provider configuration - issuer mismatch")
    void failToGetConfigurationIssuerMismatch() {
        assertThrows(SaiAuthenticationException.class, () -> { getOIDCProviderConfiguration(toMockUri(server, "/mismatch/")); });
    }

    @Test
    @DisplayName("Fail to get oidc provider configuration - missing configuration")
    void failToGetConfigurationNoConfiguration() {
        assertThrows(SaiAuthenticationException.class, () -> { getOIDCProviderConfiguration(toMockUri(server, "/missing/")); });
    }

    @Test
    @DisplayName("Get oidc issuer for social agent")
    void getIssuer() throws SaiAuthenticationException {
        URI issuer = getOidcIssuerForSocialAgent(httpClient, socialAgentId);
        assertEquals(issuer, oidcProviderId);
    }

    @Test
    @DisplayName("Fail to get oidc issuer for social agent - missing id document")
    void failToGetIssuerMissingId() {
        URI missingId = toMockUri(server, "/missing");
        assertThrows(SaiAuthenticationException.class, () -> getOidcIssuerForSocialAgent(httpClient, missingId));
    }

    @Test
    @DisplayName("Get client id document for application")
    void getClientId() throws SaiAuthenticationException, SaiRdfException {
        Resource clientIdDocument = getClientIdDocument(httpClient, clientId);
        assertNotNull(clientIdDocument);
        assertEquals(3600, getIntegerObject(clientIdDocument, SOLID_OIDC_DEFAULT_MAX_AGE));
        assertEquals("Projectron", getStringObject(clientIdDocument, SOLID_OIDC_CLIENT_NAME));
    }

    @Test
    @DisplayName("Fail to get client id document for application - missing document")
    void failToGetClientIdMissingDocument() {
        URI missingId = toMockUri(server, "/missing");
        assertThrows(SaiAuthenticationException.class, () -> getClientIdDocument(httpClient, missingId));
    }

    @Test
    @DisplayName("Get access token from Request")
    void getRequestAccessToken() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/protected");
        Headers headers = setAuthorizationHeaders(mockSession, GET, resourceUri, null);
        Request.Builder requestBuilder = new Request.Builder();
        Request request = requestBuilder.url(uriToUrl(resourceUri)).method(GET.getValue(), null).headers(headers).build();
        AccessToken token = getAccessTokenFromRequest(request);
        assertEquals(TOKEN_VALUE, token.getValue());
    }

    @Test
    @DisplayName("Fail to get token from Request - no authorization headers")
    void failToGetRequestTokenNoHeaders() throws SaiHttpException {
        URI resourceUri = toMockUri(server, "/protected");
        Request.Builder requestBuilder = new Request.Builder();
        Request request = requestBuilder.url(uriToUrl(resourceUri)).method(GET.getValue(), null).build();
        AccessToken token = getAccessTokenFromRequest(request);
        assertNull(token);
    }

    @Test
    @DisplayName("Fail to get token from Request - invalid authorization header")
    void failToGetRequestTokenInvalidHeader() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class);
        Map<String, String> authorizationHeader = Map.of(HttpHeader.AUTHORIZATION.getValue(), "INVALIDVALUE");
        when(mockSession.toHttpHeaders(any(HttpMethod.class), any(URI.class))).thenReturn(authorizationHeader);

        URI resourceUri = toMockUri(server, "/protected");
        Headers headers = setAuthorizationHeaders(mockSession, GET, resourceUri, null);
        Request.Builder requestBuilder = new Request.Builder();
        Request request = requestBuilder.url(uriToUrl(resourceUri)).method(GET.getValue(), null).headers(headers).build();
        AccessToken token = getAccessTokenFromRequest(request);
        assertNull(token);
    }

    @Test
    @DisplayName("Get a protected resource")
    void testGetProtectedResource() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/protected");
        try (Response response = getProtectedResource(mockSession, httpClient, resourceUri)) {
            assertEquals(200, response.code());
        }
    }

    @Test
    @DisplayName("Get a protected resource - with headers")
    void testGetProtectedResourceHeaders() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/protected");
        Headers headers = setHttpHeader(HttpHeader.ACCEPT, "text/*");
        try (Response response = getProtectedResource(mockSession, httpClient, resourceUri, headers)) {
            assertEquals(200, response.code());
        }
    }

    @Test
    @DisplayName("Get a protected rdf resource")
    void testGetProtectedRdfResource() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/ttl/protected");
        try (Response response = getProtectedRdfResource(mockSession, httpClient, resourceUri)) {
            assertEquals(200, response.code());
        }
    }

    @Test
    @DisplayName("Get a protected rdf resource - with headers")
    void testGetProtectedRdfResourceHeaders() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/ttl/protected");
        Headers headers = setHttpHeader(HttpHeader.ACCEPT, TEXT_TURTLE.getValue());
        try (Response response = getProtectedRdfResource(mockSession, httpClient, resourceUri, headers)) {
            assertEquals(200, response.code());
        }
    }

    // TODO - should be able to get RDF resource by content type

    @Test
    @DisplayName("Put a protected turtle resource")
    void testPutProtectedTurtleResource() throws SaiAuthenticationException, SaiRdfException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/ttl/protected");
        Model model = getModelFromString(resourceUri, getRdfBody(), TEXT_TURTLE.getValue());
        Resource resource = model.getResource(resourceUri.toString());
        Response response = putProtectedRdfResource(mockSession, httpClient, resourceUri, resource, TEXT_TURTLE);
        assertEquals(204, response.code());
    }

    @Test
    @DisplayName("Put a protected turtle resource - with headers")
    void testPutProtectedTurtleResourceHeaders() throws SaiRdfException, SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/ttl/protected");
        Model model = getModelFromString(resourceUri, getRdfBody(), TEXT_TURTLE.getValue());
        Resource resource = model.getResource(resourceUri.toString());
        Headers headers = setHttpHeader(IF_NONE_MATCH, "*");
        Response response = putProtectedRdfResource(mockSession, httpClient, resourceUri, resource, TEXT_TURTLE, headers);
        assertEquals(204, response.code());
    }

    @Test
    @DisplayName("Put a protected json-ld resource")
    void testPutProtectedJsonLdResourceHeaders() throws SaiRdfException, SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/jsonld/protected");
        Model model = getModelFromString(resourceUri, getJsonLdBody(), LD_JSON);
        Resource resource = model.getResource(resourceUri.toString());
        Response response = putProtectedRdfResource(mockSession, httpClient, resourceUri, resource, ContentType.LD_JSON, "");
        assertEquals(204, response.code());
    }

    @Test
    @DisplayName("Delete a protected resource")
    void testDeleteProtectedResourceHeaders() throws SaiAuthenticationException, SaiHttpException {
        AuthorizedSession mockSession = getMockSession(TOKEN_VALUE);
        URI resourceUri = toMockUri(server, "/protected");
        Response response = deleteProtectedResource(mockSession, httpClient, resourceUri);
        assertEquals(204, response.code());
    }

    private AuthorizedSession getMockSession(String tokenValue) throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class);
        Map<String, String> authorizationHeader = Map.of(HttpHeader.AUTHORIZATION.getValue(), "Bearer " + tokenValue);
        when(mockSession.toHttpHeaders(any(HttpMethod.class), any(URI.class))).thenReturn(authorizationHeader);
        return mockSession;
    }

    private String getRdfBody() {
        return "  PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "  PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n" +
                "  PREFIX xml: <http://www.w3.org/XML/1998/namespace>\n" +
                "  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n" +
                "  PREFIX ldp: <http://www.w3.org/ns/ldp#>\n" +
                "  PREFIX ex: <http://www.example.com/ns/ex#>\n" +
                "\n" +
                "  <>\n" +
                "    ex:uri </data/projects/project-1/#project> ;\n" +
                "    ex:id 6 ;\n" +
                "    ex:name \"Great Validations\" ;\n" +
                "    ex:created_at \"2021-04-04T20:15:47.000Z\"^^xsd:dateTime ;\n" +
                "    ex:hasMilestone </data/projects/project-1/milestone-3/#milestone> .";
    }

    private String getJsonLdBody() {
        return "{\n" +
                "  \"@context\": {\n" +
                "    \"ical\": \"http://www.w3.org/2002/12/cal/ical#\",\n" +
                "    \"xsd\": \"http://www.w3.org/2001/XMLSchema#\",\n" +
                "    \"ical:dtstart\": {\n" +
                "      \"@type\": \"xsd:dateTime\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"ical:summary\": \"Lady Gaga Concert\",\n" +
                "  \"ical:location\": \"New Orleans Arena, New Orleans, Louisiana, USA\",\n" +
                "  \"ical:dtstart\": \"2011-04-09T20:00:00Z\"\n" +
                "}";
    }

}
