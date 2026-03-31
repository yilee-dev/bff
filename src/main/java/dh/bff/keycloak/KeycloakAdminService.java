package dh.bff.keycloak;

import dh.bff.keycloak.dto.DepartmentNode;
import dh.bff.keycloak.dto.KeycloakUserDto;
import dh.bff.keycloak.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakAdminService {

    private final WebClient webClient;
    private final KeycloakAdminProperties props;

    // ─── Token 캐시 ───────────────────────────────────────────────────────────
    private record TokenInfo(String token, long expiresAt) {
        boolean isValid() { return System.currentTimeMillis() < expiresAt; }
    }
    private volatile TokenInfo cachedToken = null;

    // ─── 전체 유저 캐시 (10분 TTL) ───────────────────────────────────────────
    private static final long USER_CACHE_TTL_MS = 10 * 60 * 1000L;
    private volatile Mono<List<KeycloakUserDto>> allUsersMono = null;
    private volatile long allUsersExpiry = 0;

    private String adminBase() {
        return props.serverUrl() + "/admin/realms/" + props.realm();
    }

    private String realmBase() {
        return props.serverUrl() + "/realms/" + props.realm();
    }

    /** client_credentials 토큰 — 만료 30초 전에 자동 갱신 */
    private Mono<String> getAdminToken() {
        TokenInfo existing = cachedToken;
        if (existing != null && existing.isValid()) {
            return Mono.just(existing.token());
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", props.clientId());
        form.add("client_secret", props.clientSecret());

        return webClient.post()
                .uri(realmBase() + "/protocol/openid-connect/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .map(body -> {
                    String token = (String) body.get("access_token");
                    int expiresIn = body.get("expires_in") instanceof Number n ? n.intValue() : 300;
                    long expiresAt = System.currentTimeMillis() + (expiresIn - 30) * 1000L;
                    cachedToken = new TokenInfo(token, expiresAt);
                    return token;
                });
    }

    /**
     * 전체 유저 목록 — 10분간 메모리 캐시.
     * 한글 검색·부서 검색·트리 구성 모두 이 캐시에서 필터링.
     */
    private Mono<List<KeycloakUserDto>> fetchAllUsersCached() {
        if (allUsersMono != null && System.currentTimeMillis() < allUsersExpiry) {
            return allUsersMono;
        }
        synchronized (this) {
            long now = System.currentTimeMillis();
            if (allUsersMono == null || now >= allUsersExpiry) {
                allUsersMono = getAdminToken()
                        .flatMap(token -> getUserCount(token)
                                .flatMap(count -> fetchRaw(token, null, null, null, 0, count)))
                        .cache(); // 첫 구독 후 결과를 무기한 캐시 (TTL은 allUsersExpiry로 관리)
                allUsersExpiry = now + USER_CACHE_TTL_MS;
            }
        }
        return allUsersMono;
    }

    /** 유저 캐시를 즉시 무효화 (배정 등 변경 시 호출 가능) */
    public void invalidateUserCache() {
        synchronized (this) {
            allUsersMono = null;
            allUsersExpiry = 0;
        }
    }

    /**
     * 사용자 검색.
     * - 한글 이름 / 부서 필터: 캐시된 전체 유저에서 BFF 필터링 (Keycloak 호출 없음)
     * - 일반 검색(username·사번): Keycloak 검색 API 직접 호출
     */
    public Mono<List<UserResponse>> getUsers(String search, String department, int first, int max) {
        boolean hasSearch     = search != null && !search.isBlank();
        boolean isKorean      = isKoreanName(search);
        boolean hasDepartment = department != null && !department.isBlank();

        // 한글 이름 검색 또는 부서 필터 → 캐시 사용
        if (isKorean || hasDepartment) {
            return fetchAllUsersCached().map(list -> list.stream()
                    .filter(dto -> {
                        if (isKorean) {
                            if (dto.attributes() == null) return false;
                            List<String> vals = dto.attributes().get("displayName");
                            if (vals == null || vals.isEmpty()) return false;
                            return vals.get(0).contains(search);
                        }
                        return true;
                    })
                    .map(UserResponse::from)
                    .filter(u -> !hasDepartment
                            || (u.department() != null && u.department().equals(department)))
                    .toList());
        }

        // 검색어 없음 → 캐시 사용
        if (!hasSearch) {
            return fetchAllUsersCached().map(list -> list.stream()
                    .map(UserResponse::from)
                    .toList());
        }

        // 일반 검색(username·사번): Keycloak API 직접 호출 (결과가 소량)
        return getAdminToken().flatMap(token -> {
            Mono<List<KeycloakUserDto>> bySearch = fetchRaw(token, search, null, null, first, max);
            Mono<List<KeycloakUserDto>> byEmpNo  = fetchByAttr(token, "empNo", search, first, max);

            return Mono.zip(bySearch, byEmpNo).map(t -> {
                Map<String, KeycloakUserDto> merged = new LinkedHashMap<>();
                t.getT1().forEach(u -> merged.put(u.id(), u));
                t.getT2().forEach(u -> merged.put(u.id(), u));
                return new ArrayList<>(merged.values()).stream()
                        .map(UserResponse::from)
                        .toList();
            });
        });
    }

    /** Keycloak 커스텀 속성 검색 (q=attr:value) */
    private Mono<List<KeycloakUserDto>> fetchByAttr(
            String token, String attr, String value, int first, int max) {
        String uriString = UriComponentsBuilder
                .fromUriString(adminBase() + "/users")
                .queryParam("first", first)
                .queryParam("max", max)
                .queryParam("q", attr + ":" + value)
                .encode()
                .toUriString();

        return webClient.get()
                .uri(uriString)
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserDto>>() {});
    }

    /** 전체 사용자 수 조회 */
    private Mono<Integer> getUserCount(String token) {
        return webClient.get()
                .uri(adminBase() + "/users/count")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(Integer.class);
    }

    private Mono<List<KeycloakUserDto>> fetchRaw(
            String token, String search, String lastName, String firstName, int first, int max) {

        UriComponentsBuilder uri = UriComponentsBuilder
                .fromUriString(adminBase() + "/users")
                .queryParam("first", first)
                .queryParam("max", max);

        if (search    != null && !search.isBlank())    uri.queryParam("search",    search);
        if (lastName  != null && !lastName.isBlank())  uri.queryParam("lastName",  lastName);
        if (firstName != null && !firstName.isBlank()) uri.queryParam("firstName", firstName);

        return webClient.get()
                .uri(uri.toUriString())
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserDto>>() {});
    }

    /** 한글 이름 판별: 2~5자이고 모두 한글인 경우 */
    private boolean isKoreanName(String s) {
        if (s == null || s.length() < 2 || s.length() > 5) return false;
        return s.chars().allMatch(c -> (c >= 0xAC00 && c <= 0xD7A3)
                                   || (c >= 0x3131 && c <= 0x318E));
    }

    /**
     * 퇴직 부서 사용자 조회 — department 경로에 "퇴직"이 포함된 사용자 반환.
     * 캐시된 전체 유저에서 필터링 (별도 Keycloak 호출 없음).
     */
    public Mono<List<UserResponse>> getRetiredUsers() {
        return fetchAllUsersCached().map(list -> list.stream()
                .map(UserResponse::from)
                .filter(u -> u.department() != null && u.department().contains("퇴직"))
                .toList());
    }

    /** 특정 사용자 상세 조회 */
    public Mono<UserResponse> getUserById(String userId) {
        return getAdminToken().flatMap(token ->
                webClient.get()
                        .uri(adminBase() + "/users/" + userId)
                        .header("Authorization", "Bearer " + token)
                        .retrieve()
                        .bodyToMono(KeycloakUserDto.class)
                        .map(UserResponse::from)
        );
    }

    /**
     * 부서 트리 — 캐시된 전체 유저에서 구성 (별도 Keycloak 호출 없음).
     */
    public Mono<List<DepartmentNode>> getDepartmentTree() {
        return fetchAllUsersCached()
                .map(dtos -> dtos.stream().map(UserResponse::from).toList())
                .map(users -> {
                    Map<String, DepartmentNode> nodeMap = new LinkedHashMap<>();

                    users.stream()
                            .filter(u -> u.department() != null && !u.department().isBlank())
                            .map(UserResponse::department)
                            .filter(Objects::nonNull)
                            .distinct()
                            .sorted()
                            .forEach(deptPath -> {
                                String[] parts = deptPath.split("/");
                                StringBuilder pathBuilder = new StringBuilder();

                                for (int i = 0; i < parts.length; i++) {
                                    if (i > 0) pathBuilder.append("/");
                                    String partName = parts[i].trim();
                                    pathBuilder.append(partName);
                                    String currentPath = pathBuilder.toString();

                                    nodeMap.computeIfAbsent(currentPath, p ->
                                            new DepartmentNode(partName, p, new ArrayList<>()));

                                    if (i > 0) {
                                        String parentPath = currentPath.substring(0, currentPath.lastIndexOf("/"));
                                        DepartmentNode parent = nodeMap.get(parentPath);
                                        DepartmentNode child  = nodeMap.get(currentPath);
                                        if (parent != null && !parent.children().contains(child)) {
                                            parent.children().add(child);
                                        }
                                    }
                                }
                            });

                    return nodeMap.entrySet().stream()
                            .filter(e -> !e.getKey().contains("/"))
                            .map(Map.Entry::getValue)
                            .collect(Collectors.toList());
                });
    }
}
