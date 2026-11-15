package store.auth;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import feign.FeignException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import store.account.AccountController;
import store.account.AccountIn;
import store.account.AccountOut;

@Service
public class AuthService {

    @Autowired
    private AccountController accountController;

    @Autowired
    private JwtService jwtService;

    @Value("${store.jwt.duration}")
    private Long duration;

    @Value("${store.jwt.httpOnly}")
    private Boolean httpOnly;

    // bottleneck (circuit breaker): se o account cair, falhamos rápido com 503
    // em vez de segurar threads esperando timeout (ver resilience4j em application.yaml)
    @CircuitBreaker(name = "account", fallbackMethod = "createFallback")
    public void create(Register register) {
        accountController.create(AccountIn.builder()
            .name(register.name())
            .email(register.email())
            .password(register.password())
            .build());
    }

    @CircuitBreaker(name = "account", fallbackMethod = "loginFallback")
    public String login(String email, String password) {
        final AccountOut account;
        try {
            // o account calcula o hash da senha e compara com o armazenado
            account = accountController.login(AccountIn.builder().email(email).password(password).build()).getBody();
        } catch (FeignException.Unauthorized | FeignException.BadRequest e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        return jwtService.generate(account, getDuration());
    }

    @CircuitBreaker(name = "account", fallbackMethod = "meFallback")
    public AccountOut me(String idAccount) {
        return accountController.findById(idAccount).getBody();
    }

    public Map<String, String> solve(String jwt) {
        return Map.of("idAccount", jwtService.getId(jwt));
    }

    public long getDuration() {
        return duration;
    }

    public boolean getHttpOnly() {
        return httpOnly;
    }

    private void createFallback(Register register, RuntimeException e) { throw translate(e); }
    private String loginFallback(String email, String password, RuntimeException e) { throw translate(e); }
    private AccountOut meFallback(String idAccount, RuntimeException e) { throw translate(e); }

    // 4xx do account passa adiante (400, 404, 409); falha de rede/5xx ou circuito aberto vira 503
    static RuntimeException translate(RuntimeException e) {
        if (e instanceof ResponseStatusException) return e;
        if (e instanceof FeignException f && f.status() >= 400 && f.status() < 500) {
            return new ResponseStatusException(HttpStatusCode.valueOf(f.status()));
        }
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "account service unavailable", e);
    }

}
