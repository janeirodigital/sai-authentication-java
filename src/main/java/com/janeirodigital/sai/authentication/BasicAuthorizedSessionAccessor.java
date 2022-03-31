package com.janeirodigital.sai.authentication;

import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Basic in-memory implementation of {@link AuthorizedSessionAccessor} when the consumer
 * of sai-java doesn't provide their own implementation.
 */
@Slf4j
public class BasicAuthorizedSessionAccessor implements AuthorizedSessionAccessor {

    private static final String DIGEST_ALGORITHM = "SHA-512";
    private final ConcurrentHashMap<String, AuthorizedSession> sessions;

    /**
     * Initializes a new Concurrent (thread safe) Hash Map for storage and retrieval
     * of an {@link AuthorizedSession}
     */
    public BasicAuthorizedSessionAccessor() { this.sessions = new ConcurrentHashMap<>(); }

    /**
     * Gets the provided {@link AuthorizedSession} from the in-memory store
     * @param session {@link AuthorizedSession} to get
     * @return {@link AuthorizedSession} matching the provided session or null
     */
    @Override
    public AuthorizedSession get(AuthorizedSession session) throws SaiAuthenticationException {
        return this.sessions.get(session.getId(DIGEST_ALGORITHM));
    }

    /**
     * Searches the in-memory session store for an {@link AuthorizedSession} with the same access token value
     * as the one in the provided <code>accessToken</code>.
     * @param accessToken Access token to lookup session with
     * @return {@link AuthorizedSession} matching the provided access token or null
     */
    @Override
    public AuthorizedSession get(AccessToken accessToken) {
        return this.sessions.searchValues(1, value -> {
            if (accessToken.getValue().equals(value.getAccessToken().getValue())) { return value; } else { return null; }
        });
    }

    @Override
    public AuthorizedSession get(URI socialAgentId, URI applicationId, URI oidcProviderId) throws SaiAuthenticationException {
        String identifier = AuthorizedSession.generateId(DIGEST_ALGORITHM, socialAgentId, applicationId, oidcProviderId);
        return this.sessions.get(identifier);
    }

    /**
     * Refreshes the {@link AuthorizedSession} and updates the in-memory session store with the new values
     * @param session {@link AuthorizedSession} to refresh
     * @return Refreshed {@link AuthorizedSession}
     */
    @Override
    public AuthorizedSession refresh(AuthorizedSession session) throws SaiAuthenticationException {
        session.refresh();
        this.sessions.replace(session.getId(DIGEST_ALGORITHM), session);
        return session;
    }

    /**
     * Updates in-memory session store with the provided {@link AuthorizedSession}
     * @param session session to store
     * @throws SaiAuthenticationException
     */
    public void store(AuthorizedSession session) throws SaiAuthenticationException { this.sessions.put(session.getId(DIGEST_ALGORITHM), session); }

    /**
     * Returns the size of the in-memory session store
     * @return number of sessions
     */
    public int size() { return this.sessions.size(); }

}
