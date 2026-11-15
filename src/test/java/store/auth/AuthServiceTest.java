package store.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import store.account.AccountOut;

class AuthServiceTest {

    private JwtService jwt(String key) {
        JwtService s = new JwtService();
        ReflectionTestUtils.setField(s, "secretKey", key);
        return s;
    }

    private static final String KEY = "EBwrdOOcAIDRLON9hbJV0+O3PTdfTjgMCQIxwLH7ws8=";
    private static final AccountOut ANA = AccountOut.builder().id("42").name("Ana").email("ana@insper.edu.br").build();

    @Test
    void tokenCarriesTheAccountId() {
        JwtService s = jwt(KEY);
        assertEquals("42", s.getId(s.generate(ANA, 60_000)));
    }

    @Test
    void tokenSignedWithAnotherKeyIs401() {
        String forged = jwt("c2VjcmV0LWtleS1kZS1vdXRyby1zZXJ2aWRvci0xMjM=").generate(ANA, 60_000);
        var e = assertThrows(ResponseStatusException.class, () -> jwt(KEY).getId(forged));
        assertEquals(401, e.getStatusCode().value());
    }

    @Test
    void expiredTokenIs401() {
        JwtService s = jwt(KEY);
        String expired = s.generate(ANA, -1_000);
        assertEquals(401, assertThrows(ResponseStatusException.class, () -> s.getId(expired)).getStatusCode().value());
    }

    @Test
    void openCircuitBecomes503() {
        var open = CallNotPermittedException.createCallNotPermittedException(CircuitBreaker.ofDefaults("account"));
        var e = (ResponseStatusException) AuthService.translate(open);
        assertEquals(503, e.getStatusCode().value());
    }

}
