package dh.bff.oauth2.filter;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;


public class CsrfCookieWebFilter implements WebFilter {

    private final ServerCsrfTokenRepository csrfTokenRepository;

    public CsrfCookieWebFilter(ServerCsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return csrfTokenRepository.loadToken(exchange)
                .switchIfEmpty(Mono.defer(() -> csrfTokenRepository.generateToken(exchange)
                        .delayUntil(csrfToken -> csrfTokenRepository.saveToken(exchange, csrfToken))))
                .doOnNext(CsrfToken::getToken)
                .then(chain.filter(exchange));
    }
}
