package dh.bff.constant;

import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

public class GatewayInfo {
    public static final String GATEWAY = "10.117.9.40";
    public static final String PORT = "8080";

    public static final String PROTOCOL = "http";

    public static String getGatewayUrl() {
        return PROTOCOL + "://" + GATEWAY + ":" + PORT;
    }

    public static String getGatewayWith(String url) {
        return PROTOCOL + "://" + GATEWAY + ":" + PORT + "/" + url;
    }

    public static String endSessionOut(String idToken) {
        String endPoint = getGatewayWith("realms/donghee/protocol/openid-connect/logout");

        return String.format(
                endPoint,
                "?id_token_hint=%s" + "&post_logout_redirect_uri=%s",
                idToken,
                getGatewayUrl()
        );
    }
}
