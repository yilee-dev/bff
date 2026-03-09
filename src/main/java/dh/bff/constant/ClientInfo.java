package dh.bff.constant;

public class ClientInfo {
    public static final String CLIENT = "10.117.9.40";
    public static final String PORT = "3000";
    public static final String PROTOCOL = "https";

    public static String getClientInfo() {
        return PROTOCOL + "://" + CLIENT + ":" + PORT;
    }

    public static String getURL(String url) {
        return getClientInfo() + "/" + url;
    }
}
