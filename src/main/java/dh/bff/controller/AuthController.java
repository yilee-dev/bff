package dh.bff.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final WebClient webClient;

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
