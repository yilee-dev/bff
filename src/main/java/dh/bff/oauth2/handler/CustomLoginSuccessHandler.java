package dh.bff.oauth2.handler;

import dh.bff.repository.OriginPreservingRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

import java.net.URI;

public class CustomLoginSuccessHandler extends RedirectServerAuthenticationSuccessHandler {

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        var exchange = webFilterExchange.getExchange();

        // Keycloak 콜백 URL의 state 쿼리 파라미터 = 어떤 탭/프론트엔드가 시작한 요청인지 식별
        String state = exchange.getRequest().getQueryParams().getFirst("state");
        if (state == null) {
            this.setLocation(URI.create("/"));
            return super.onAuthenticationSuccess(webFilterExchange, authentication);
        }

        return OriginPreservingRepository.consumeClientOrigin(exchange, state)
                .defaultIfEmpty("/")
                .flatMap(clientUrl -> {
                    String url = clientUrl.endsWith("/")
                            ? clientUrl.substring(0, clientUrl.length() - 1)
                            : clientUrl;
                    this.setLocation(URI.create(url));
                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                });
    }
}
