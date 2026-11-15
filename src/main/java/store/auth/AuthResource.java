package store.auth;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import store.account.AccountOut;

@RestController
public class AuthResource implements AuthController {

    @Autowired
    private AuthService authService;

    @Override
    public ResponseEntity<Void> create(RegisterIn in) {
        authService.create(AuthParser.to(in));
        return ResponseEntity.ok().build();
    }

    @Override
    public ResponseEntity<Void> login(LoginIn in) {
        final String token = authService.login(in.email(), in.password());
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie(token, authService.getDuration()).toString())
            .build();
    }

    @Override
    public ResponseEntity<AccountOut> me(String idAccount) {
        return ResponseEntity.ok(authService.me(idAccount));
    }

    @Override
    public ResponseEntity<Map<String, String>> solveToken(TokenOut token) {
        return ResponseEntity.ok(authService.solve(token.token()));
    }

    @Override
    public ResponseEntity<Void> logout() {
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie(null, 0L).toString())
            .build();
    }

    @Override
    public ResponseEntity<Void> healthCheck() {
        return ResponseEntity.ok().build();
    }

    private ResponseCookie cookie(String content, long duration) {
        return ResponseCookie.from(AUTH_COOKIE_TOKEN, content)
            .httpOnly(authService.getHttpOnly())
            .sameSite("None")
            .secure(true)
            .path("/")
            .maxAge(Duration.ofMillis(duration))
            .build();
    }

}
