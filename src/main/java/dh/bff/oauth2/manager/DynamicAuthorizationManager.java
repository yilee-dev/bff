package dh.bff.oauth2.manager;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class DynamicAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private static final String AUTH_MAP_KEY = "AUTH_MAP";

    @Override
    public Mono<Void> verify(Mono<Authentication> authentication, AuthorizationContext object) {
        return ReactiveAuthorizationManager.super.verify(authentication, object);
    }

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext object) {
        ServerWebExchange exchange = object.getExchange();
        String requestPath = exchange.getRequest().getPath().value();
        String requestMethod = exchange.getRequest().getMethod().name();

        return redisTemplate.opsForHash().entries(AUTH_MAP_KEY)
                .filter(entry -> {
                    String[] keyParts = entry.getKey().toString().split(":");
                    if (keyParts.length < 2) return false;

                    String configMethod = keyParts[0];
                    String configPath = keyParts[1];

                    boolean methodMatch = configMethod.equals("*") || configMethod.equalsIgnoreCase(requestMethod);
                    boolean pathMatch = pathMatcher.match(configPath, requestPath);

                    return methodMatch && pathMatch;
                })
                .map(entry -> entry.getValue().toString())
                .collectList()
                .flatMap(requiredRoles -> {
                    // 매칭되는 규칙이 없으면 인증만 확인
                    if (requiredRoles.isEmpty()) {
                        return authentication
                                .map(Authentication::isAuthenticated)
                                .map(AuthorizationDecision::new)
                                .defaultIfEmpty(new AuthorizationDecision(false));
                    }

                    return authentication
                            .filter(Authentication::isAuthenticated)
                            .flatMapIterable(Authentication::getAuthorities)
                            .map(GrantedAuthority::getAuthority)
                            .any(grantedAuth -> requiredRoles.stream()
                                    .anyMatch(role -> grantedAuth.equals("ROLE_" + role)))
                            .map(AuthorizationDecision::new)
                            .defaultIfEmpty(new AuthorizationDecision(false));
                });
    }
}
