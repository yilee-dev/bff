package dh.bff.controller;

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
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final WebClient webClient;

    @GetMapping("/me")
    public Mono<ResponseEntity<Map<String, Object>>> getUserInfo(@AuthenticationPrincipal OAuth2User oidcUser) {
        Map<String, Object> attributes1 = oidcUser.getAttributes();
        for (String s : attributes1.keySet()) {
            System.out.println(s + ": " + attributes1.get(s));
        }
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
                    return ResponseEntity.ok(response);
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/sign-out")
    public Mono<ResponseEntity<Void>> signOut(WebSession session, @AuthenticationPrincipal OidcUser oidcUser) {

        if (oidcUser == null || oidcUser.getIdToken() == null) {
            return session.invalidate()
                    .then(Mono.just(ResponseEntity.ok().<Void>build()));
        }

        String idToken = oidcUser.getIdToken().getTokenValue();

        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .scheme("http")
                        .host("10.100.104.24")
                        .port(8080)
                        .path("/realms/donghee/protocol/openid-connect/logout")
                        .queryParam("id_token_hint", idToken)
                        .build())
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> {
                    log.error(e.getMessage());
                    return Mono.empty();
                })
                .then(session.invalidate())
                .then(Mono.just(ResponseEntity.ok().<Void>build()));
    }
}
