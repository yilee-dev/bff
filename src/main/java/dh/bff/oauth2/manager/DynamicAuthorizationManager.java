package dh.bff.oauth2.manager;

import dh.bff.oauth2.config.AuthRuleInitializer;
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

import java.util.Comparator;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class DynamicAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext object) {
        ServerWebExchange exchange = object.getExchange();
        String requestPath = exchange.getRequest().getPath().value();
        String requestMethod = exchange.getRequest().getMethod().name();

        // 패턴 특이도 비교자 — 구체적인 패턴이 앞에 오도록 정렬
        Comparator<String> pathSpecificity = pathMatcher.getPatternComparator(requestPath);

        return redisTemplate.opsForHash().<Object, Object>entries(AuthRuleInitializer.AUTH_MAP_KEY)
                .filter(entry -> {
                    String[] parts = entry.getKey().toString().split(":", 2);
                    if (parts.length < 2) return false;
                    String ruleMethod = parts[0];
                    String rulePath  = parts[1];
                    boolean methodMatch = ruleMethod.equals("*") || ruleMethod.equalsIgnoreCase(requestMethod);
                    boolean pathMatch   = pathMatcher.match(rulePath, requestPath);
                    return methodMatch && pathMatch;
                })
                .collectList()
                .flatMap(matched -> {
                    if (matched.isEmpty()) {
                        // 등록된 규칙 없음 → 인증만 확인 (신규 서비스는 Admin UI로 규칙 추가)
                        return authentication
                                .map(Authentication::isAuthenticated)
                                .map(AuthorizationDecision::new)
                                .defaultIfEmpty(new AuthorizationDecision(false));
                    }

                    // 가장 구체적인 패턴 하나만 적용 (first-match)
                    matched.sort(Comparator.comparing(
                            (Map.Entry<Object, Object> e) -> e.getKey().toString().split(":", 2)[1],
                            pathSpecificity
                    ));
                    String requiredAuthority = matched.get(0).getValue().toString();

                    return authentication
                            .filter(Authentication::isAuthenticated)
                            .flatMapIterable(Authentication::getAuthorities)
                            .map(GrantedAuthority::getAuthority)
                            .any(granted -> granted.equals(requiredAuthority))
                            .map(AuthorizationDecision::new)
                            .defaultIfEmpty(new AuthorizationDecision(false));
                });
    }
}
