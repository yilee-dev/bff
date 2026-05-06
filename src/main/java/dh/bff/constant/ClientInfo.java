package dh.bff.constant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ClientInfo {

    private static String clientUrl;

    @Value("${app.client.url:http://10.117.9.40:3000}")
    public void setClientUrl(String url) {
        ClientInfo.clientUrl = url;
    }

    public static String getClientInfo() {
        return clientUrl;
    }

    public static String getURL(String path) {
        return clientUrl + "/" + path;
    }
}
