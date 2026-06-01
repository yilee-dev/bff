package dh.bff.opensearch.dto;

public record InboundPort(
        String dstIp,
        int dstPort,
        long count,
        long uniqueSources
) {}
