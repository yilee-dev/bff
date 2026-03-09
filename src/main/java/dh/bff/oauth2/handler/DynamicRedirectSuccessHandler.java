package dh.bff.oauth2.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Objects;

public class DynamicRedirectSuccessHandler extends RedirectServerAuthenticationSuccessHandler {
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        return webFilterExchange.getExchange().getSession()
                .flatMap(session -> {
                    String clientUrl = session.getAttribute("CLIENT_ORIGIN_URL");

                    this.setLocation(URI.create(Objects.requireNonNullElse(clientUrl, "/")));

                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                });
    }
}
