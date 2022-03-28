package com.janeirodigital.sai.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BasicAuthorizedSessionAccessorTests {

    private static URL oidcProviderId;
    private static URL socialAgentId;
    private static URL applicationId;
    private static AccessToken accessToken;
    private static AccessToken updatedAccessToken;
    
    @BeforeEach
    void beforeEach() throws MalformedURLException {
        oidcProviderId = new URL("https://op.example/");
        socialAgentId = new URL("https://acme.example/id#org");
        applicationId = new URL("https://projectron.example/id#app");
        accessToken = new AccessToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkstRmFpSTJwMW9ybjA2SkVRUWEwZTBwY1ZPTkNGLUtJOEFLV0lHN2ZOTW8ifQ.eyJ3ZWJpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9wcm9maWxlL2NhcmQjbWUiLCJjbGllbnRfaWQiOiJodHRwOi8vbG9jYWxob3N0OjcwNzAvcHJvamVjdHJvbiIsImp0aSI6IkwxNjI0X3p5OWx6WXFvQ1pvTWNXSSIsInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9wcm9maWxlL2NhcmQjbWUiLCJpYXQiOjE2NDMwNjA4NTIsImV4cCI6MTY0MzA2NDQ1Miwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBvZmZsaW5lX2FjY2VzcyIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC8iLCJhdWQiOiJzb2xpZCIsImF6cCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcm9qZWN0cm9uIiwiY25mIjp7ImprdCI6IlpXaW40SVo1S1hyQWI1RzBjNWFkOFEyR3ZFLWRLS1QtTTJ0dEhwTURzSFUifX0.rXd7BQMpjbC0QJeU3OEx0d8qaPvG6Zldyf6XLsksnYAEMQ_kpOp6miBFiK_y800DisO8Ub9_muYC28rHsg-DrKb-bOt7EZSNdwWeLWP9VMVxO73LAE5XUDrFGvNgmUm2dGXXLN930jYmCT-4Ca1U83fZ39tyCsSVGpajMfJuDjQLbAHH1qUdGAfWOJQcbpZw1FmI5jhctZPh3CVKQTKZ8j7OWFYWpCWNso-m_hxS3l0mjXzfzLB3yf_VXP9Pe2NtWlD29vS0HiCwCTtiDvB0Vdll6pHgHUvHvA_nLRrNLHEK1vxBlOo3zoFJvyVz5GBXyRljctjBWstxOPFeyuDuKw");
        updatedAccessToken = new AccessToken("eyJhbGciOiTSzI1MiIsInR5cCI6IkpXVCIsImtpZCI6IkstRmFpSTJwMW9ybjA2SkVRUWEwZTBwY1ZPTkNGLUtJOEFLV0lHN2ZOTW8ifQ.eyJ3ZWJpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9wcm9maWxlL2NhcmQjbWUiLCJjbGllbnRfaWQiOiJodHRwOi8vbG9jYWxob3N0OjcwNzAvcHJvamVjdHJvbiIsImp0aSI6IkwxNjI0X3p5OWx6WXFvQ1pvTWNXSSIsInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9wcm9maWxlL2NhcmQjbWUiLCJpYXQiOjE2NDMwNjA4NTIsImV4cCI6MTY0MzA2NDQ1Miwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBvZmZsaW5lX2FjY2VzcyIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC8iLCJhdWQiOiJzb2xpZCIsImF6cCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcm9qZWN0cm9uIiwiY25mIjp7ImprdCI6IlpXaW40SVo1S1hyQWI1RzBjNWFkOFEyR3ZFLWRLS1QtTTJ0dEhwTURzSFUifX0.rXd7BQMpjbC0QJeU3OEx0d8qaPvG6Zldyf6XLsksnYAEMQ_kpOp6miBFiK_y800DisO8Ub9_muYC28rHsg-DrKb-bOt7EZSNdwWeLWP9VMVxO73LAE5XUDrFGvNgmUm2dGXXLN930jYmCT-4Ca1U83fZ39tyCsSVGpajMfJuDjQLbAHH1qUdGAfWOJQcbpZw1FmI5jhctZPh3CVKQTKZ8j7OWFYWpCWNso-m_hxS3l0mjXzfzLB3yf_VXP9Pe2NtWlD29vS0HiCwCTtiDvB0Vdll6pHgHUvHvA_nLRrNLHEK1vxBlOo3zoFJvyVz5GBXyRljctjBWstxOPFeyuDuKw");
    }

    @Test
    @DisplayName("Initialize basic authorized session accessor")
    void initAccessor() {
        BasicAuthorizedSessionAccessor accessor = new BasicAuthorizedSessionAccessor();
        assertNotNull(accessor);
        assertEquals(0, accessor.size());
    }

    @Test
    @DisplayName("Get a session by session identifier")
    void getSessionById() throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        BasicAuthorizedSessionAccessor accessor = new BasicAuthorizedSessionAccessor();
        accessor.store(mockSession);
        assertEquals(mockSession, accessor.get(mockSession));
    }

    @Test
    @DisplayName("Get a session by social agent, application, and oidc provider")
    void getSessionByAgentsAndProvider() throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        BasicAuthorizedSessionAccessor accessor = new BasicAuthorizedSessionAccessor();
        accessor.store(mockSession);
        assertEquals(mockSession, accessor.get(socialAgentId, applicationId, oidcProviderId));
    }

    @Test
    @DisplayName("Lookup a session that doesn't exist")
    void getSessionDoesNotExist() throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        BasicAuthorizedSessionAccessor accessor = new BasicAuthorizedSessionAccessor();
        assertNull(accessor.get(mockSession));
    }

    @Test
    @DisplayName("Get a session by access token")
    void getSessionByToken() throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        when(mockSession.getAccessToken()).thenReturn(accessToken);
        BasicAuthorizedSessionAccessor accessor = new BasicAuthorizedSessionAccessor();
        accessor.store(mockSession);
        assertEquals(mockSession, accessor.get(mockSession.getAccessToken()));
        AuthorizedSession otherSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(otherSession.getAccessToken()).thenReturn(updatedAccessToken);
        assertNull(accessor.get(otherSession.getAccessToken()));
    }

    @Test
    @DisplayName("Refresh a session")
    void refreshSession() throws SaiAuthenticationException {
        AuthorizedSession mockSession = mock(AuthorizedSession.class, CALLS_REAL_METHODS);
        when(mockSession.getSocialAgentId()).thenReturn(socialAgentId);
        when(mockSession.getApplicationId()).thenReturn(applicationId);
        when(mockSession.getOidcProviderId()).thenReturn(oidcProviderId);
        when(mockSession.getAccessToken()).thenReturn(accessToken);
        BasicAuthorizedSessionAccessor accessor = new BasicAuthorizedSessionAccessor();
        accessor.store(mockSession);
        assertNotNull(accessor.refresh(mockSession));
    }

}
