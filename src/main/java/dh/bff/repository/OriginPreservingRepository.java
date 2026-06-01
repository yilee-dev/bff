package dh.bff.repository;

import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class OriginPreservingRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String AUTH_REQUEST_MAP_ATTR = "OAUTH2_AUTH_REQUEST_MAP";
    public static final String CLIENT_ORIGIN_MAP_ATTR = "CLIENT_ORIGIN_MAP";

    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
        String state = exchange.getRequest().getQueryParams().getFirst("state");
        if (state == null) return Mono.empty();

        return exchange.getSession().flatMap(session -> {
            Map<String, OAuth2AuthorizationRequest> requestMap = session.getAttribute(AUTH_REQUEST_MAP_ATTR);
            if (requestMap == null) return Mono.empty();
            return Mono.justOrEmpty(requestMap.get(state));
        });
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
        return exchange.getSession().flatMap(session -> {
            if (authorizationRequest == null) {
                return Mono.empty();
            }

            String state = authorizationRequest.getState();

            Map<String, OAuth2AuthorizationRequest> requestMap =
                    session.getAttributeOrDefault(AUTH_REQUEST_MAP_ATTR, new HashMap<>());
            requestMap.put(state, authorizationRequest);
            session.getAttributes().put(AUTH_REQUEST_MAP_ATTR, requestMap);

            String origin = exchange.getRequest().getHeaders().getFirst("Referer");
            if (origin == null || origin.isEmpty()) {
                URI uri = exchange.getRequest().getURI();
                origin = uri.getScheme() + "://" + uri.getAuthority();
            }

            Map<String, String> originMap =
                    session.getAttributeOrDefault(CLIENT_ORIGIN_MAP_ATTR, new HashMap<>());
            originMap.put(state, origin);
            session.getAttributes().put(CLIENT_ORIGIN_MAP_ATTR, originMap);

            return Mono.empty();
        }).then();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
        String state = exchange.getRequest().getQueryParams().getFirst("state");
        if (state == null) return Mono.empty();

        return exchange.getSession().flatMap(session -> {
            Map<String, OAuth2AuthorizationRequest> requestMap = session.getAttribute(AUTH_REQUEST_MAP_ATTR);
            if (requestMap == null) return Mono.empty();

            OAuth2AuthorizationRequest removed = requestMap.remove(state);
            session.getAttributes().put(AUTH_REQUEST_MAP_ATTR, requestMap);
            return Mono.justOrEmpty(removed);
        });
    }

    /**
     * 로그인 성공 핸들러에서 리다이렉트할 프론트엔드 URL을 꺼낼 때 사용
     */
    public static Mono<String> consumeClientOrigin(ServerWebExchange exchange, String state) {
        return exchange.getSession().flatMap(session -> {
            Map<String, String> originMap = session.getAttribute(CLIENT_ORIGIN_MAP_ATTR);
            if (originMap == null) return Mono.empty();
            String origin = originMap.remove(state);
            session.getAttributes().put(CLIENT_ORIGIN_MAP_ATTR, originMap);
            return Mono.justOrEmpty(origin);
        });
    }
}
