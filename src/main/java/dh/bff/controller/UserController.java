package dh.bff.controller;

import dh.bff.keycloak.KeycloakAdminService;
import dh.bff.keycloak.dto.DepartmentNode;
import dh.bff.keycloak.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/bff")
@RequiredArgsConstructor
public class UserController {

    private final KeycloakAdminService keycloakAdminService;

    @GetMapping("/users")
    public Mono<ResponseEntity<List<UserResponse>>> getUsers(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String department,
            @RequestParam(defaultValue = "0") int first,
            @RequestParam(defaultValue = "100") int max
    ) {
        return keycloakAdminService.getUsers(search, department, first, max)
                .map(ResponseEntity::ok);
    }

    @GetMapping("/users/{userId}")
    public Mono<ResponseEntity<UserResponse>> getUserById(@PathVariable String userId) {
        return keycloakAdminService.getUserById(userId)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @GetMapping("/users/retired")
    public Mono<ResponseEntity<List<UserResponse>>> getRetiredUsers() {
        return keycloakAdminService.getRetiredUsers()
                .map(ResponseEntity::ok);
    }

    @GetMapping("/departments")
    public Mono<ResponseEntity<List<DepartmentNode>>> getDepartments() {
        return keycloakAdminService.getDepartmentTree()
                .map(ResponseEntity::ok);
    }
}
