package dh.bff.constant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class GatewayInfo {

    private static String gatewayUrl;

    @Value("${keycloak.admin.server-url:http://10.100.104.24:8080}")
    public void setGatewayUrl(String url) {
        GatewayInfo.gatewayUrl = url;
    }

    public static String getGatewayUrl() {
        return gatewayUrl;
    }

    public static String getGatewayWith(String path) {
        return gatewayUrl + "/" + path;
    }
}
