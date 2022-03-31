package com.janeirodigital.sai.authentication;

import com.janeirodigital.sai.httputils.*;
import com.janeirodigital.sai.rdfutils.SaiRdfException;
import com.janeirodigital.sai.rdfutils.SaiRdfNotFoundException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static com.janeirodigital.sai.authentication.SolidTermsVocabulary.SOLID_OIDC_ISSUER;
import static com.janeirodigital.sai.httputils.HttpHeader.AUTHORIZATION;
import static com.janeirodigital.sai.httputils.HttpMethod.*;
import static com.janeirodigital.sai.httputils.HttpUtils.*;
import static com.janeirodigital.sai.rdfutils.RdfUtils.getRequiredUriObject;
import static com.janeirodigital.sai.rdfutils.RdfUtils.getResourceFromModel;

/**
 * Assorted helper methods related to working with OAuth2 / OpenID Connect sessions, tokens,
 * and authorization servers. Makes liberal use of the
 * <a href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus SDK</a>.
 */
public class AuthorizedSessionHelper {

    private static final Set<String> AUTHORIZATION_HEADER_SCHEMES = Set.of("Bearer", "DPoP");

    private AuthorizedSessionHelper() { }

    public static URI getOidcIssuerForSocialAgent(OkHttpClient httpClient, URI socialAgentId) throws SaiAuthenticationException {
        Objects.requireNonNull(httpClient, "Must provide an http client to lookup issuer");
        Objects.requireNonNull(socialAgentId, "Must provide a social agent identity to lookup issuer");
        try (Response response = getRequiredRdfResource(httpClient, socialAgentId)) {
            Model dataset = getRdfModelFromResponse(response);
            Resource resource = getResourceFromModel(dataset, socialAgentId);
            return getRequiredUriObject(resource, SOLID_OIDC_ISSUER);
        } catch (SaiRdfNotFoundException | SaiHttpException | SaiHttpNotFoundException | SaiRdfException ex) {
            throw new SaiAuthenticationException("Unable to get OpenID Connect provider for " + socialAgentId, ex);
        }
    }

    /**
     * Get the configuration of an OpenID Provider based on the discovery and contents
     * of its .well-known/openid-configuration resource.
     * @param providerUri URI of the OpenID Provider
     * @return OIDCProviderMetadata
     * @throws SaiAuthenticationException
     */
    public static OIDCProviderMetadata getOIDCProviderConfiguration(URI providerUri) throws SaiAuthenticationException {
        Objects.requireNonNull(providerUri, "Must provide an openid provider URI to discover provider metadata");
        Issuer issuer = new Issuer(providerUri.toString());
        OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);
        HTTPRequest httpRequest = request.toHTTPRequest();
        HTTPResponse httpResponse;
        OIDCProviderMetadata metadata;
        try {
            httpRequest.setAccept("*/*");
            httpResponse = httpRequest.send();
            if (!httpResponse.indicatesSuccess()) { throw new IOException("Request failed to " + providerUri); }
            metadata = OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());
            if (!issuer.equals(metadata.getIssuer())) { throw new SaiAuthenticationException("Issuer mismatch: Supplied issuer " + issuer.getValue() + "is a different value than that received from OP: " + metadata.getIssuer().getValue()); }
        } catch (IOException | ParseException| SaiAuthenticationException ex) {
            throw new SaiAuthenticationException("Unable to lookup OpenID Provider configuration for " + providerUri, ex);
        }
        return metadata;
    }

    /**
     * Get the client identifier document as a Jena Resource associated with the provided <code>clientId</code>
     * @param httpClient OkHttpClient to perform the GET with
     * @param clientId URI of the client identifier to get
     * @return Jena RDF Resource
     * @throws SaiAuthenticationException
     */
    public static Resource getClientIdDocument(OkHttpClient httpClient, URI clientId) throws SaiAuthenticationException {
        Objects.requireNonNull(httpClient, "Must provide an http client to lookup client id document");
        Objects.requireNonNull(clientId, "Must provide a client identity to lookup client id document");
        try (Response response = getRequiredRdfResource(httpClient, clientId)) {
            Model dataset = getRdfModelFromResponse(response);
            return getResourceFromModel(dataset, clientId);
        } catch (SaiHttpException | SaiHttpNotFoundException ex) {
            throw new SaiAuthenticationException("Unable to load client identifier document for " + clientId, ex);
        }
    }

    /**
     * Gets a protected resource that requires additional Authorization headers to be added to the request.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the GET with
     * @param uri URI of the resource to GET
     * @param headers Optional OkHttp Headers
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response getProtectedResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Headers headers) throws SaiAuthenticationException, SaiHttpException {
        Objects.requireNonNull(authorizedSession, "Must provide an authorized session to access protected resource");
        headers = setAuthorizationHeaders(authorizedSession, GET, uri, headers);
        return getResource(httpClient, uri, headers);
    }

    /**
     * Calls {@link #getProtectedResource(AuthorizedSession, OkHttpClient, URI, Headers)} with no additional
     * headers provided.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the GET with
     * @param uri URI of the resource to GET
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response getProtectedResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri) throws SaiAuthenticationException, SaiHttpException {
        return getProtectedResource(authorizedSession, httpClient, uri, null);
    }

    /**
     * Gets a protected RDF resource that requires additional Authorization headers to be added to the request.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the GET with
     * @param uri URI of the resource to GET
     * @param headers Optional OkHttp Headers
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response getProtectedRdfResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Headers headers) throws SaiAuthenticationException, SaiHttpException {
        Objects.requireNonNull(authorizedSession, "Must provide an authorized session to access protected resource");
        headers = setAuthorizationHeaders(authorizedSession, GET, uri, headers);
        return getRdfResource(httpClient, uri, headers);
    }

    /**
     * Calls {@link #getProtectedRdfResource(AuthorizedSession, OkHttpClient, URI, Headers)} with no additional
     * headers provided.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the GET with
     * @param uri URI of the resource to GET
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response getProtectedRdfResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri) throws SaiAuthenticationException, SaiHttpException {
        return getProtectedRdfResource(authorizedSession, httpClient, uri, null);
    }

    /**
     * Puts a protected RDF resource that requires additional Authorization headers to be added to the request.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the PUT with
     * @param uri URI of the resource to PUT
     * @param resource Jena resource to PUT with
     * @param contentType ContentType of the request
     * @param jsonLdContext Optional JSON-LD context string to include
     * @param headers Optional OkHttp Headers
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response putProtectedRdfResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Resource resource, ContentType contentType, String jsonLdContext, Headers headers) throws SaiAuthenticationException, SaiHttpException {
        Objects.requireNonNull(authorizedSession, "Must provide an authorized session to access protected resource");
        headers = setAuthorizationHeaders(authorizedSession, PUT, uri, headers);
        return putRdfResource(httpClient, uri, resource, contentType, jsonLdContext, headers);
    }

    /**
     * Calls {@link #putProtectedRdfResource(AuthorizedSession, OkHttpClient, URI, Resource, ContentType, String, Headers)} with no additional
     * headers provided.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the PUT with
     * @param uri URI of the resource to PUT
     * @param resource Jena resource to PUT with
     * @param contentType ContentType of the request
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response putProtectedRdfResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Resource resource, ContentType contentType) throws SaiAuthenticationException, SaiHttpException {
        return putProtectedRdfResource(authorizedSession, httpClient, uri, resource, contentType, null, null);
    }

    /**
     * Calls {@link #putProtectedRdfResource(AuthorizedSession, OkHttpClient, URI, Resource, ContentType, String, Headers)} with
     * additional headers provided
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the PUT with
     * @param uri URI of the resource to PUT
     * @param resource Jena resource to PUT with
     * @param contentType ContentType of the request
     * @param headers Optional OkHttp Headers
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response putProtectedRdfResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Resource resource, ContentType contentType, Headers headers) throws SaiAuthenticationException, SaiHttpException {
        return putProtectedRdfResource(authorizedSession, httpClient, uri, resource, contentType, null, headers);
    }

    /**
     * Calls {@link #putProtectedRdfResource(AuthorizedSession, OkHttpClient, URI, Resource, ContentType, String, Headers)} with
     * additional headers provided
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the PUT with
     * @param uri URI of the resource to PUT
     * @param resource Jena resource to PUT with
     * @param contentType ContentType of the request
     * @param jsonLdContext Optional JSON-LD context string to include
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response putProtectedRdfResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Resource resource, ContentType contentType, String jsonLdContext) throws SaiAuthenticationException, SaiHttpException {
        return putProtectedRdfResource(authorizedSession, httpClient, uri, resource, contentType, jsonLdContext, null);
    }

    /**
     * Deletes a protected resource that requires additional Authorization headers to be added to the request.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the DELETE with
     * @param uri URI of the resource to DELETE
     * @param headers Optional OkHttp Headers
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response deleteProtectedResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri, Headers headers) throws SaiAuthenticationException, SaiHttpException {
        Objects.requireNonNull(authorizedSession, "Must provide an authorized session to access protected resource");
        headers = setAuthorizationHeaders(authorizedSession, DELETE, uri, headers);
        return deleteResource(httpClient, uri, headers);
    }

    /**
     * Calls {@link #deleteProtectedResource(AuthorizedSession, OkHttpClient, URI, Headers)} with no additional
     * headers provided.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param httpClient OkHttpClient to perform the DELETE with
     * @param uri URI of the resource to DELETE
     * @return OkHttp Response
     * @throws SaiAuthenticationException
     */
    public static Response deleteProtectedResource(AuthorizedSession authorizedSession, OkHttpClient httpClient, URI uri) throws SaiAuthenticationException, SaiHttpException {
        return deleteProtectedResource(authorizedSession, httpClient, uri, null);
    }

    /**
     * Sets the appropriate HTTP Authorization headers based on the characteristics of the {@link AuthorizedSession}.
     * @param authorizedSession {@link AuthorizedSession} for access to protected resources
     * @param method {@link HttpMethod} of the request
     * @param uri Target URI of the request
     * @param headers Optional OkHttp Headers
     * @return Populated OkHttp Headers
     */
    public static Headers setAuthorizationHeaders(AuthorizedSession authorizedSession, HttpMethod method, URI uri, Headers headers) throws SaiAuthenticationException {
        Objects.requireNonNull(authorizedSession, "Must provide an authorized session to set authorization headers");
        Objects.requireNonNull(method, "Must provide an HTTP method to set authorization headers");
        Objects.requireNonNull(uri, "Must provide a target URI to set authorization headers");
        for (Map.Entry<String, String> entry : authorizedSession.toHttpHeaders(method, uri).entrySet()) {
            headers = setHttpHeader(HttpHeader.get(entry.getKey()), entry.getValue(), headers);
        }
        return headers;
    }

    /**
     * Extracts the value of an access token from the Authorization header of an HTTP request. Returns
     * null if no Authorization header exists or the token type isn't recognized.
     * @param request OkHttp Request
     * @return Access token value or null
     */
    public static AccessToken getAccessTokenFromRequest(Request request) {
        Objects.requireNonNull(request, "Must provide an HTTP request to get token from");
        String value = request.header(AUTHORIZATION.getValue());
        if (value == null) { return null; }
        String[] split = value.split("\\s");
        if (!AUTHORIZATION_HEADER_SCHEMES.contains(split[0])) { return null; }
        return new AccessToken(split[1]);
    }

    /**
     * Translates a nimbus native AccessToken into the generic sai-java format
     * @param nimbusAccessToken Nimbus AccessToken
     * @return AccessToken in sai-java format
     */
    public static AccessToken translateAccessToken(com.nimbusds.oauth2.sdk.token.AccessToken nimbusAccessToken) {
        Objects.requireNonNull(nimbusAccessToken, "Must provide an access token to translate");
        return new AccessToken(nimbusAccessToken.toString());
    }

    /**
     * Translates a nimbus native AccessToken into the generic sai-java format
     * @param nimbusRefreshToken Nimbus RefreshToken
     * @return RefreshToken in sai-java format
     */
    public static RefreshToken translateRefreshToken(com.nimbusds.oauth2.sdk.token.RefreshToken nimbusRefreshToken) {
        Objects.requireNonNull(nimbusRefreshToken, "Must provide a refresh token to translate");
        return new RefreshToken(nimbusRefreshToken.toString());
    }

}
