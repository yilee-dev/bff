package dh.bff.keycloak.dto;

import java.util.List;

public record DepartmentNode(
        String name,
        String path,
        List<DepartmentNode> children
) {}
