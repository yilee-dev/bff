package dh.bff.opensearch.dto;

import java.util.List;

public record NetworkTrafficResponse(
        List<InboundPort> inboundPorts,
        List<TopologyConnection> connections,
        boolean fromCache
) {}
