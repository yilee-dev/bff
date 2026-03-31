package dh.bff.keycloak.dto;

public record UserResponse(
        String id,
        String username,
        String givenName,
        String familyName,
        String name,
        String email,
        String empNo,
        String department,          // 트리 탐색용 전체 경로 (예: "동희그룹/CFO/경영정보실/지속가능경영팀")
        String departmentName,      // 표시용 부서명 (예: "지속가능경영팀")
        String companyCode,         // 회사(법인) 코드 — extensionName 마지막 값 앞 4자리
        String businessSiteCode,    // 사업장 코드 — extensionName 마지막 값 뒤 4자리
        Boolean enabled
) {
    public static UserResponse from(KeycloakUserDto dto) {
        String name = (dto.lastName() != null && dto.firstName() != null)
                ? dto.lastName() + dto.firstName()
                : dto.username();
        return new UserResponse(
                dto.id(),
                dto.username(),
                dto.firstName(),
                dto.lastName(),
                name,
                dto.email(),
                dto.empNo(),
                dto.department(),
                dto.departmentDisplayName(),
                dto.companyCode(),
                dto.businessSiteCode(),
                dto.enabled()
        );
    }
}
