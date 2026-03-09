package dh.bff.oauth2.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class LogoutOriginPreservingHandler implements ServerLogoutHandler {
    public static final String LOGOUT_REDIRECT_ATTR = "LOGOUT_ORIGINAL_URL";

    @Override
    public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
        return exchange.getExchange().getSession().map(session -> {
            String referer = exchange.getExchange().getRequest().getHeaders().getFirst("Referer");
            if (referer != null && !referer.isEmpty()) {
                session.getAttributes().put(LOGOUT_REDIRECT_ATTR, referer);
            }
            return session;
        }).then();
    }
}
