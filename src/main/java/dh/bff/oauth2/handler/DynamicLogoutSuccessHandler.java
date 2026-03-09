package dh.bff.oauth2.handler;

import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;

public class DynamicLogoutSuccessHandler implements ServerLogoutSuccessHandler {
    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        return exchange.getExchange().getSession().flatMap(session -> {
            String targetUrl = session.getAttribute(LogoutOriginPreservingHandler.LOGOUT_REDIRECT_ATTR);

            if (targetUrl == null) {
                targetUrl = "/";
            }

            session.getAttributes().remove(LogoutOriginPreservingHandler.LOGOUT_REDIRECT_ATTR);
            ServerHttpResponse response = exchange.getExchange().getResponse();
            response.getHeaders().setLocation(URI.create(targetUrl));
            return response.setComplete();
        });
    }
}
