package dh.bff.opensearch.dto;

import java.util.List;

public record TopologyConnection(
        String srcIp,
        String dstIp,
        List<Integer> ports,
        long count
) {}
