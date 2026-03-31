package dh.bff.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record KeycloakUserDto(
        String id,
        String username,
        String firstName,
        String lastName,
        String email,
        Boolean enabled,
        Map<String, List<String>> attributes
) {
    public String empNo() {
        return getAttribute("empNo");
    }

    /**
     * 트리 탐색용 전체 부서 경로.
     * LDAP_ENTRY_DN의 OU 계층을 역순으로 연결합니다.
     * 예) CN=yuna.yup,OU=지속가능경영팀,OU=경영정보실,OU=CFO,...
     *   → "동희그룹/총괄사장/CEO/CFO/경영정보실/지속가능경영팀"
     */
    public String departmentPath() {
        String dn = getAttribute("LDAP_ENTRY_DN");
        if (dn == null || dn.isBlank()) return null;

        List<String> ous = new ArrayList<>();
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("OU=")) {
                String ouName = trimmed.substring(3);
                // 최상단 기술적 OU(DONGHEE, 조직단위, 그룹사)는 제외
                if (!isAdminOu(ouName)) {
                    ous.add(ouName);
                }
            }
        }
        if (ous.isEmpty()) return null;

        Collections.reverse(ous);
        return String.join("/", ous);
    }

    /**
     * 표시용 부서명.
     * dept 속성(형식: "코드;이름") → 이름 부분 반환.
     * 없으면 departmentPath의 마지막 세그먼트.
     */
    public String departmentDisplayName() {
        String dept = getAttribute("dept");
        if (dept != null && dept.contains(";")) {
            return dept.substring(dept.indexOf(";") + 1);
        }
        String path = departmentPath();
        if (path == null) return null;
        int idx = path.lastIndexOf("/");
        return idx >= 0 ? path.substring(idx + 1) : path;
    }

    /** 트리/필터 기준이 되는 부서 경로 */
    public String department() {
        return departmentPath();
    }

    /**
     * extensionName 파싱: "근무지|값2|값3|CCCCBBBB"
     * CCCC = 회사(법인) 코드 앞 4자리, BBBB = 사업장 코드 뒤 4자리
     */
    public String companyCode() {
        return parseExtensionNamePart(0);
    }

    public String businessSiteCode() {
        return parseExtensionNamePart(1);
    }

    private String parseExtensionNamePart(int offset) {
        String[] parts = extensionNameParts();
        if (parts == null) return null;
        // 마지막 비어있지 않은 값
        String last = null;
        for (int i = parts.length - 1; i >= 0; i--) {
            if (!parts[i].isBlank()) { last = parts[i].trim(); break; }
        }
        if (last == null || last.length() < 8) return null;
        return offset == 0 ? last.substring(0, 4) : last.substring(4, 8);
    }

    private String[] extensionNameParts() {
        String ext = getAttribute("extensionName");
        if (ext == null || ext.isBlank()) return null;
        return ext.split("\\|");
    }

    private boolean isAdminOu(String ou) {
        // 최상위 LDAP 구조용 OU — 실제 조직 단위가 아님
        return ou.equalsIgnoreCase("DONGHEE")
                || ou.equals("조직단위")
                || ou.equals("그룹사");
    }

    private String getAttribute(String key) {
        if (attributes == null) return null;
        List<String> values = attributes.get(key);
        return (values != null && !values.isEmpty()) ? values.get(0) : null;
    }
}
