package dh.bff.opensearch.dto;

import java.util.List;

public record PeerConnection(String peerIp, List<Integer> ports, long packetCount) {}
