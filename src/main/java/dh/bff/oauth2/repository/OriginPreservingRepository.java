package dh.bff.oauth2.repository;

import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class OriginPreservingRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String AUTH_REQUEST_ATTR = "OAUTH2_AUTH_REQUEST";
    private static final String CLIENT_ORIGIN_URL = "CLIENT_ORIGIN_URL";

    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
        return exchange.getSession()
                .map(session -> session.getAttribute(AUTH_REQUEST_ATTR));
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
        return exchange.getSession().flatMap(session -> {
            if (authorizationRequest == null) {
                session.getAttributes().remove(AUTH_REQUEST_ATTR);
                return Mono.empty();
            }

            session.getAttributes().put(AUTH_REQUEST_ATTR, authorizationRequest);

            String origin = exchange.getRequest().getHeaders().getFirst("Referer");
            if (origin == null || origin.isEmpty()) {
                URI uri = exchange.getRequest().getURI();
                origin = uri.getScheme() + "://" + uri.getAuthority();
            }

            session.getAttributes().put(CLIENT_ORIGIN_URL, origin);
            return Mono.empty();
        }).then();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
        return exchange.getSession().map(session -> {
            OAuth2AuthorizationRequest request = session.getAttribute(AUTH_REQUEST_ATTR);
            session.getAttributes().remove(AUTH_REQUEST_ATTR);
            return request;
        });
    }
}
