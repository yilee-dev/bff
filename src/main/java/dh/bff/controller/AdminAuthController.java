package dh.bff.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/auth")
@RequiredArgsConstructor
public class AdminAuthController {

    private static final String AUTH_MAP_KEY = "AUTH_MAP";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    /** 전체 규칙 조회 */
    @GetMapping("/rules")
    public Mono<ResponseEntity<List<Map<String, String>>>> getRules() {
        return redisTemplate.opsForHash().entries(AUTH_MAP_KEY)
                .map(entry -> {
                    String[] keyParts = entry.getKey().toString().split(":", 2);
                    return Map.of(
                            "method", keyParts.length >= 1 ? keyParts[0] : "",
                            "pathPattern", keyParts.length >= 2 ? keyParts[1] : "",
                            "role", entry.getValue().toString()
                    );
                })
                .collect(Collectors.toList())
                .map(ResponseEntity::ok);
    }

    /** 규칙 추가/수정 */
    @PostMapping("/rules")
    public Mono<ResponseEntity<Void>> addRule(@RequestBody Map<String, String> body) {
        String method = body.get("method");
        String pathPattern = body.get("pathPattern");
        String role = body.get("role");

        if (method == null || pathPattern == null || role == null) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

        String key = method.toUpperCase() + ":" + pathPattern;
        return redisTemplate.opsForHash().put(AUTH_MAP_KEY, key, role)
                .thenReturn(ResponseEntity.ok().build());
    }

    /** 규칙 삭제 */
    @DeleteMapping("/rules")
    public Mono<ResponseEntity<Void>> removeRule(@RequestBody Map<String, String> body) {
        String method = body.get("method");
        String pathPattern = body.get("pathPattern");

        if (method == null || pathPattern == null) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

        String key = method.toUpperCase() + ":" + pathPattern;
        return redisTemplate.opsForHash().remove(AUTH_MAP_KEY, key)
                .thenReturn(ResponseEntity.ok().build());
    }
}
