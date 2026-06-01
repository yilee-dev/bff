package dh.bff.opensearch.dto;

import java.util.List;

public record PortInfo(int port, long packetCount, long uniqueSources, List<String> topSources) {}
