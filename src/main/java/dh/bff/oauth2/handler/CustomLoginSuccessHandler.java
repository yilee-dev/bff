package dh.bff.oauth2.handler;

import dh.bff.constant.ClientInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

import java.net.URI;

public class CustomLoginSuccessHandler extends RedirectServerAuthenticationSuccessHandler {
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        String redirectUrl = ClientInfo.getClientInfo();
        this.setLocation(URI.create(redirectUrl));
        return super.onAuthenticationSuccess(webFilterExchange, authentication);
    }
}
