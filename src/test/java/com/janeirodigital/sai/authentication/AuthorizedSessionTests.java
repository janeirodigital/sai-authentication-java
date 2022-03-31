package com.janeirodigital.sai.authentication;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class AuthorizedSessionTests {

    private static URI oidcProviderId;
    private static URI socialAgentId;
    private static URI applicationId;

    @BeforeAll
    static void beforeAll() {
        oidcProviderId = URI.create("https://op.example/");
        socialAgentId = URI.create("https://acme.example/id#org");
        applicationId = URI.create("https://projectron.example/id#app");
    }

    @Test
    @DisplayName("Get session id")
    void getSessionId() throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        assertNotNull(mockSession.getId("SHA-512"));
    }

    @Test
    @DisplayName("Get session id")
    void failToGetSessionId() {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        assertThrows(SaiAuthenticationException.class, () -> mockSession.getId("SHA-HAHA"));
    }

}
