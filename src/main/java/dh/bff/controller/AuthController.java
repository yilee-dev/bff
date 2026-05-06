package dh.bff.controller;

import dh.bff.keycloak.KeycloakAdminProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final WebClient webClient;
    private final KeycloakAdminProperties keycloakProps;

    @GetMapping("/me")
    public Mono<ResponseEntity<Map<String, Object>>> getUserInfo(@AuthenticationPrincipal OAuth2User oidcUser) {
        return Mono.justOrEmpty(oidcUser)
                .map(user -> {
                    Map<String, Object> attributes = user.getAttributes();
                    Map<String, Object> response = new HashMap<>();

                    response.put("username", attributes.get("preferred_username"));
                    response.put("givenName", attributes.get("given_name"));
                    response.put("familyName", attributes.get("family_name"));
                    response.put("name", attributes.get("name"));
                    response.put("email", attributes.get("email"));
                    response.put("empNo", attributes.get("empNo"));

                    if (attributes.containsKey("realm_access")) {
                        Object o = attributes.get("realm_access");
                        if (o instanceof Map<?, ?> realmAccess) {
                            response.put("roles", realmAccess.get("roles"));
                        }
                    }

                    // resource_access.api-gateway.roles에서 permissions 추출
                    if (attributes.containsKey("resource_access")) {
                        Object ra = attributes.get("resource_access");
                        if (ra instanceof Map<?, ?> resourceAccess) {
                            Object clientAccess = resourceAccess.get("api-gateway");
                            if (clientAccess instanceof Map<?, ?> ca) {
                                response.put("permissions", ca.get("roles"));
                            }
                        }
                    }

                    return ResponseEntity.ok(response);
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/sign-out")
    public Mono<ResponseEntity<Void>> signOut(WebSession session, @AuthenticationPrincipal OidcUser oidcUser) {
        if (oidcUser == null || oidcUser.getIdToken() == null) {
            log.warn("sign-out 호출 시 oidcUser 또는 idToken이 null — 세션만 무효화합니다.");
            return session.invalidate()
                    .then(Mono.just(ResponseEntity.ok().<Void>build()));
        }

        String idToken = oidcUser.getIdToken().getTokenValue();

        URI logoutUri = UriComponentsBuilder
                .fromUriString(keycloakProps.serverUrl())
                .path("/realms/{realm}/protocol/openid-connect/logout")
                .queryParam("id_token_hint", idToken)
                .buildAndExpand(keycloakProps.realm())
                .toUri();

        log.info("Keycloak 로그아웃 요청: {}", logoutUri);

        return webClient.get()
                .uri(logoutUri)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(res -> log.info("Keycloak 로그아웃 성공: {}", res.getStatusCode()))
                .onErrorResume(e -> {
                    log.error("Keycloak 로그아웃 실패: {}", e.getMessage(), e);
                    return Mono.empty();
                })
                .then(session.invalidate())
                .then(Mono.just(ResponseEntity.ok().<Void>build()));
    }
}
