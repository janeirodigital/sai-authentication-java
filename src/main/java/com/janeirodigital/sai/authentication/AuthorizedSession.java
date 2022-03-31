package com.janeirodigital.sai.authentication;

import com.janeirodigital.sai.httputils.HttpMethod;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;

/**
 * Interface implemented by different types of authorized sessions, typically
 * different types of OAuth2/OIDC flows. Keeps sai-java classes that require
 * credentials to access protected resources from having to care about the specifics
 * of how those credentials are acquired and maintained. See {@link SolidOidcSession} and
 * {@link ClientCredentialsSession} for implementation examples.
 */
public interface AuthorizedSession extends Serializable {

    /**
     * Gets the URI of the SocialAgent identity associated with the {@link AuthorizedSession}
     * @return URI of SocialAgent identity
     */
    URI getSocialAgentId();

    /**
     * Gets the URI of the Application identity associated with the {@link AuthorizedSession}
     * @return URI of Application identity
     */
    URI getApplicationId();

    /**
     * Gets the URI of the OIDC Provider that issued the tokens for the {@link AuthorizedSession}
     * @return URI of Application identity
     */
    URI getOidcProviderId();

    /**
     * Gets the {@link AccessToken} associated with the {@link AuthorizedSession}
     * @return {@link AccessToken}
     */
    AccessToken getAccessToken();

    /**
     * Gets the {@link RefreshToken} associated with the {@link AuthorizedSession}
     * @return {@link RefreshToken}
     */
    RefreshToken getRefreshToken();

    /**
     * Generates a map of HTTP authorization headers that can be added to an HTTP request when
     * accessing protected resources. Some types of sessions (e.g. DPoP) need to know the
     * HTTP method and target URI of the request to generate the headers.
     * @param method HTTP method of the request
     * @param uri Target URI of the request
     * @return Map of Authorization Headers
     */
    Map<String, String> toHttpHeaders(HttpMethod method, URI uri) throws SaiAuthenticationException;

    /**
     * Refreshes the token(s) associated with the {@link AuthorizedSession}
     * @throws SaiAuthenticationException
     */
    void refresh() throws SaiAuthenticationException;

    /**
     * Default method that returns a consistent session identifier across implementations
     * for an authorized session scoped to the social agent, application id, and openid provider.
     * @param algorithm Message digest algorithm to use
     * @return String identifier of an authorized session
     */
    static String generateId(String algorithm, URI socialAgentId, URI applicationId, URI oidcProviderId) throws SaiAuthenticationException {
        Objects.requireNonNull(socialAgentId, "Must provide a social agent identifier for session id generation");
        Objects.requireNonNull(applicationId, "Must provide an application identifier for session id generation");
        Objects.requireNonNull(oidcProviderId, "Must provide an oidc provider identifier for session id generation");
        String combined = socialAgentId.toString() + applicationId.toString() + oidcProviderId.toString();
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] messageDigest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            BigInteger no = new BigInteger(1, messageDigest);
            return no.toString(16);
        } catch (NoSuchAlgorithmException ex) {
            throw new SaiAuthenticationException("Failed to generate identifier for authorized session", ex);
        }
    }

    default String getId(String algorithm) throws SaiAuthenticationException {
        return generateId(algorithm, getSocialAgentId(), getApplicationId(), getOidcProviderId());
    }

}
