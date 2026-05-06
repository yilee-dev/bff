package dh.bff.oauth2.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String CLIENT_ID = "api-gateway";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        // realm roles → ROLE_ 접두사
        Object realmAccess = jwt.getClaim("realm_access");
        if (realmAccess instanceof Map<?, ?> map) {
            authorities.addAll(extractRoles(map, "ROLE_"));
        }

        // api-gateway client roles → 접두사 없음 (backend PermissionsConverter와 동일)
        Object resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess instanceof Map<?, ?> map) {
            Object clientAccess = map.get(CLIENT_ID);
            if (clientAccess instanceof Map<?, ?> clientMap) {
                authorities.addAll(extractRoles(clientMap, ""));
            }
        }

        return authorities;
    }

    private List<SimpleGrantedAuthority> extractRoles(Map<?, ?> map, String prefix) {
        Object roles = map.get("roles");
        if (roles instanceof Collection<?> roleList) {
            return roleList.stream()
                    .filter(String.class::isInstance)
                    .map(role -> new SimpleGrantedAuthority(prefix + role))
                    .toList();
        }
        return Collections.emptyList();
    }
}
