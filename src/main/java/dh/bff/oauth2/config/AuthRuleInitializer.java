package dh.bff.oauth2.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * 애플리케이션 시작 시 application.yml의 app.auth.default-rules를 Redis AUTH_MAP에 적재.
 *
 * - 기본 규칙(default-rules)은 항상 덮어씌워 application.yml 변경이 재배포 후 즉시 반영됨.
 * - Admin UI로 추가된 동적 규칙(기본 규칙 키에 없는 경로)은 그대로 유지됨.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthRuleInitializer implements ApplicationRunner {

    public static final String AUTH_MAP_KEY = "AUTH_MAP";

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final AuthRuleProperties properties;

    @Override
    public void run(ApplicationArguments args) {
        Map<String, String> defaults = properties.getDefaultRules().stream()
                .collect(Collectors.toMap(
                        AuthRuleProperties.RuleEntry::toRedisKey,
                        AuthRuleProperties.RuleEntry::getAuthority,
                        (a, b) -> a  // 중복 키 발생 시 첫 번째 유지
                ));

        if (defaults.isEmpty()) {
            log.warn("No default auth rules configured in app.auth.default-rules");
            return;
        }

        log.info("Loading {} default auth rules into Redis AUTH_MAP", defaults.size());
        redisTemplate.opsForHash()
                .putAll(AUTH_MAP_KEY, defaults)
                .doOnSuccess(v -> log.info("Default auth rules applied successfully"))
                .doOnError(e -> log.error("Failed to load default auth rules", e))
                .subscribe();
    }
}
