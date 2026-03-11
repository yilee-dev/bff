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
//        String redirectUrl = ClientInfo.getClientInfo();
//        this.setLocation(URI.create(redirectUrl));
//
//        ServerWebExchange exchange = webFilterExchange.getExchange();
//
//        return exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.<CsrfToken>empty())
//                .doOnNext(CsrfToken::getToken)
//                .then(super.onAuthenticationSuccess(webFilterExchange, authentication));
        return webFilterExchange.getExchange().getSession()
                .flatMap(session -> {
                    String clientUrl = session.getAttribute(OriginPreservingRepository.CLIENT_ORIGIN_URL);

                    if (clientUrl != null) {
                        this.setLocation(URI.create(clientUrl));
                    } else {
                        this.setLocation(URI.create("/"));
                    }

                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                });
    }
}
