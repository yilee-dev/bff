package dh.bff.oauth2.handler;

import dh.bff.constant.ClientInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.WebFilterExchange;
import reactor.core.publisher.Mono;

public class CustomLogoutSuccessHandler extends OidcClientInitiatedServerLogoutSuccessHandler {
    public CustomLogoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        super(clientRegistrationRepository);
        setPostLogoutRedirectUri(ClientInfo.getClientInfo());
    }

    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        return super.onLogoutSuccess(exchange, authentication);
    }
}
