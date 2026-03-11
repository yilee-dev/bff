package dh.bff.oauth2.filter;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class SpaCsrfTokenFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String key = CsrfToken.class.getName();
        Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(key, Mono.empty());

        return csrfToken
                .flatMap(token -> {
                    String actualToken = token.getToken();
                    exchange.getResponse().getHeaders().set("X-CSRF-TOKEN", actualToken);
                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }
}
