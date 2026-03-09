package dh.bff.oauth2.filter;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class CsrfTokenResponseHeaderFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            return csrfToken.flatMap(token -> {
                exchange.getResponse().getHeaders().set(token.getHeaderName(), token.getToken());
                return chain.filter(exchange);
            });
        }
        return chain.filter(exchange);
    }
}
