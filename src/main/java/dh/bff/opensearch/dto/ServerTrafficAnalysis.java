package dh.bff.opensearch.dto;

import java.util.List;

public record ServerTrafficAnalysis(
        String targetIp,
        List<PortInfo> inboundPorts,
        List<PeerConnection> outboundConnections,
        boolean fromCache
) {}
