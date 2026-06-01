package dh.bff.controller;

import dh.bff.opensearch.NetworkTrafficService;
import dh.bff.opensearch.dto.ServerTrafficAnalysis;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/bff/network-traffic")
@RequiredArgsConstructor
public class NetworkTrafficController {

    private final NetworkTrafficService networkTrafficService;

    @GetMapping("/server-analysis")
    public Mono<ResponseEntity<ServerTrafficAnalysis>> getServerAnalysis(
            @RequestParam String ip) {
        return networkTrafficService.getServerAnalysis(ip)
                .map(ResponseEntity::ok);
    }

    @DeleteMapping("/cache")
    public Mono<Boolean> invalidateCache(
            @RequestParam(required = false) String ip) {
        return networkTrafficService.invalidateCache(ip);
    }
}
