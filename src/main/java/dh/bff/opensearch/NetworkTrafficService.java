package dh.bff.opensearch;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import dh.bff.opensearch.dto.PeerConnection;
import dh.bff.opensearch.dto.PortInfo;
import dh.bff.opensearch.dto.ServerTrafficAnalysis;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class NetworkTrafficService {

    private static final String CACHE_PREFIX = "network-traffic:server:";

    private final WebClient openSearchClient;
    private final OpenSearchProperties props;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public NetworkTrafficService(
            @Qualifier("openSearchWebClient") WebClient openSearchClient,
            OpenSearchProperties props,
            ReactiveStringRedisTemplate redisTemplate,
            ObjectMapper objectMapper) {
        this.openSearchClient = openSearchClient;
        this.props = props;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    public Mono<ServerTrafficAnalysis> getServerAnalysis(String ip) {
        String cacheKey = CACHE_PREFIX + ip;
        return redisTemplate.opsForValue().get(cacheKey)
                .flatMap(cached -> {
                    try {
                        ServerTrafficAnalysis result = objectMapper.readValue(cached, ServerTrafficAnalysis.class);
                        log.info("Cache hit for IP: {}", ip);
                        return Mono.just(new ServerTrafficAnalysis(
                                result.targetIp(), result.inboundPorts(), result.outboundConnections(), true));
                    } catch (Exception e) {
                        log.warn("Cache parse failed for IP: {}", ip, e);
                        return Mono.empty();
                    }
                })
                .switchIfEmpty(fetchAndCache(ip, cacheKey));
    }

    public Mono<Boolean> invalidateCache(String ip) {
        if (ip != null && !ip.isBlank()) {
            return redisTemplate.delete(CACHE_PREFIX + ip).map(c -> c > 0);
        }
        return redisTemplate.delete(redisTemplate.keys(CACHE_PREFIX + "*")).map(c -> c > 0);
    }

    private Mono<ServerTrafficAnalysis> fetchAndCache(String ip, String cacheKey) {
        log.info("Fetching traffic analysis from OpenSearch for IP: {}", ip);
        return Mono.zip(fetchInboundPorts(ip), fetchOutboundConnections(ip))
                .map(tuple -> new ServerTrafficAnalysis(ip, tuple.getT1(), tuple.getT2(), false))
                .flatMap(analysis -> {
                    try {
                        String json = objectMapper.writeValueAsString(analysis);
                        return redisTemplate.opsForValue()
                                .set(cacheKey, json, Duration.ofHours(24))
                                .doOnSuccess(ok -> log.info("Cached analysis for IP: {}", ip))
                                .thenReturn(analysis);
                    } catch (Exception e) {
                        log.error("Failed to cache analysis for IP: {}", ip, e);
                        return Mono.just(analysis);
                    }
                });
    }

    // ── 인바운드: 이 IP로 들어오는 포트별 트래픽 ──────────────────────────

    private Mono<List<PortInfo>> fetchInboundPorts(String ip) {
        byte[] body = objectMapper.writeValueAsBytes(buildInboundQuery(ip));
        return openSearchClient.post()
                .uri("/" + props.getIndex() + "/_search")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .onStatus(org.springframework.http.HttpStatusCode::isError, res ->
                        res.bodyToMono(String.class)
                                .doOnNext(err -> log.error("OpenSearch inbound error {}: {}", res.statusCode(), err))
                                .flatMap(err -> Mono.error(new RuntimeException("OpenSearch " + res.statusCode()))))
                .bodyToMono(JsonNode.class)
                .map(this::parseInboundPorts)
                .doOnSuccess(ports -> log.info("Inbound ports for {}: {} entries", ip, ports.size()))
                .retryWhen(connectionResetRetry("inbound"));
    }

    private ObjectNode buildInboundQuery(String ip) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("size", 0);
        root.put("timeout", "30s");

        root.putObject("query").putObject("term").put("destination.ip.keyword", ip);

        ObjectNode portsAgg = root.putObject("aggs").putObject("ports");
        ObjectNode portTerms = portsAgg.putObject("terms");
        portTerms.put("field", "destination.port");
        portTerms.put("size", 65535);

        ObjectNode portSubAggs = portsAgg.putObject("aggs");

        ObjectNode topSrcAgg = portSubAggs.putObject("top_sources");
        ObjectNode topSrcTerms = topSrcAgg.putObject("terms");
        topSrcTerms.put("field", "source.ip.keyword");
        topSrcTerms.put("size", 10);

        ObjectNode cardAgg = portSubAggs.putObject("unique_src_count").putObject("cardinality");
        cardAgg.put("field", "source.ip.keyword");
        cardAgg.put("precision_threshold", 100);

        return root;
    }

    private List<PortInfo> parseInboundPorts(JsonNode response) {
        List<PortInfo> result = new ArrayList<>();
        response.path("aggregations").path("ports").path("buckets").forEach(portBucket -> {
            int port = portBucket.path("key").asInt();
            long count = portBucket.path("doc_count").asLong();
            long uniqueSrc = portBucket.path("unique_src_count").path("value").asLong();
            List<String> topSources = new ArrayList<>();
            portBucket.path("top_sources").path("buckets")
                    .forEach(srcBucket -> topSources.add(srcBucket.path("key").asText()));
            result.add(new PortInfo(port, count, uniqueSrc, topSources));
        });
        return result;
    }

    // ── 아웃바운드: 이 IP에서 나가는 연결 ────────────────────────────────

    private Mono<List<PeerConnection>> fetchOutboundConnections(String ip) {
        byte[] body = objectMapper.writeValueAsBytes(buildOutboundQuery(ip));
        return openSearchClient.post()
                .uri("/" + props.getIndex() + "/_search")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .onStatus(org.springframework.http.HttpStatusCode::isError, res ->
                        res.bodyToMono(String.class)
                                .doOnNext(err -> log.error("OpenSearch outbound error {}: {}", res.statusCode(), err))
                                .flatMap(err -> Mono.error(new RuntimeException("OpenSearch " + res.statusCode()))))
                .bodyToMono(JsonNode.class)
                .map(this::parseOutboundConnections)
                .doOnSuccess(conns -> log.info("Outbound connections for {}: {} peers", ip, conns.size()))
                .retryWhen(connectionResetRetry("outbound"));
    }

    private ObjectNode buildOutboundQuery(String ip) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("size", 0);
        root.put("timeout", "30s");

        ArrayNode filter = root.putObject("query").putObject("bool").putArray("filter");
        filter.addObject().putObject("term").put("source.ip.keyword", ip);
        filter.addObject().putObject("prefix").put("destination.ip.keyword", "10.");

        ObjectNode dstAgg = root.putObject("aggs").putObject("dst_ips");
        ObjectNode dstTerms = dstAgg.putObject("terms");
        dstTerms.put("field", "destination.ip.keyword");
        dstTerms.put("size", 200);

        ObjectNode portsAgg = dstAgg.putObject("aggs").putObject("ports");
        ObjectNode portTerms = portsAgg.putObject("terms");
        portTerms.put("field", "destination.port");
        portTerms.put("size", 20);

        return root;
    }

    private List<PeerConnection> parseOutboundConnections(JsonNode response) {
        List<PeerConnection> result = new ArrayList<>();
        response.path("aggregations").path("dst_ips").path("buckets").forEach(dstBucket -> {
            String peerIp = dstBucket.path("key").asText();
            long count = dstBucket.path("doc_count").asLong();
            List<Integer> ports = new ArrayList<>();
            dstBucket.path("ports").path("buckets")
                    .forEach(portBucket -> ports.add(portBucket.path("key").asInt()));
            result.add(new PeerConnection(peerIp, ports, count));
        });
        return result;
    }

    private Retry connectionResetRetry(String label) {
        return Retry.max(1)
                .filter(e -> e instanceof WebClientRequestException wce
                        && wce.getCause() instanceof IOException)
                .doBeforeRetry(s -> log.warn("OpenSearch {} connection reset, retrying (attempt {})",
                        label, s.totalRetries() + 1));
    }
}
