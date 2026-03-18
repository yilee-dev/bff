package dh.bff.oauth2.handler;

import dh.bff.constant.ClientInfo;
import dh.bff.repository.OriginPreservingRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

public class CustomLoginSuccessHandler extends RedirectServerAuthenticationSuccessHandler {
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        return webFilterExchange.getExchange().getSession()
                .flatMap(session -> {
                    String clientUrl = session.getAttribute(OriginPreservingRepository.CLIENT_ORIGIN_URL);
                    if (clientUrl != null) {
                        if (clientUrl.endsWith("/")) {
                            clientUrl = clientUrl.substring(0, clientUrl.length() - 1);
                        }
                        this.setLocation(URI.create(clientUrl));
                    } else {
                        this.setLocation(URI.create("/"));
                    }

                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                });
    }
}
