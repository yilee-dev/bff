package dh.bff.oauth2.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * Keycloak은 기본적으로 ID 토큰에 resource_access(client roles)를 포함하지 않는다.
 * 로그인 시 access 토큰을 디코딩해 resource_access를 ID 토큰 claims에 병합함으로써
 * userAuthoritiesMapper와 AuthController가 client roles를 읽을 수 있도록 한다.
 */
@Component
@RequiredArgsConstructor
public class KeycloakOidcUserService extends OidcReactiveOAuth2UserService {

    private final ReactiveJwtDecoder jwtDecoder;

    @Override
    public Mono<OidcUser> loadUser(OidcUserRequest userRequest) {
        return super.loadUser(userRequest).flatMap(oidcUser -> {
            if (oidcUser.getIdToken().getClaims().containsKey("resource_access")) {
                return Mono.just(oidcUser);
            }

            String accessTokenValue = userRequest.getAccessToken().getTokenValue();

            return jwtDecoder.decode(accessTokenValue)
                    .map(accessJwt -> {
                        Object resourceAccess = accessJwt.getClaim("resource_access");
                        if (resourceAccess == null) {
                            return oidcUser;
                        }

                        Map<String, Object> mergedClaims = new HashMap<>(oidcUser.getIdToken().getClaims());
                        mergedClaims.put("resource_access", resourceAccess);

                        OidcIdToken mergedIdToken = new OidcIdToken(
                                oidcUser.getIdToken().getTokenValue(),
                                oidcUser.getIdToken().getIssuedAt(),
                                oidcUser.getIdToken().getExpiresAt(),
                                mergedClaims
                        );

                        return (OidcUser) new DefaultOidcUser(
                                oidcUser.getAuthorities(),
                                mergedIdToken,
                                oidcUser.getUserInfo()
                        );
                    })
                    .onErrorResume(e -> Mono.just(oidcUser));
        });
    }
}
