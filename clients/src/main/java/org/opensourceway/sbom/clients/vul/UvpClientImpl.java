package org.opensourceway.sbom.clients.vul;

import org.opensourceway.sbom.api.vul.UvpClient;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.UvpVulnerabilityReport;
import org.opensourceway.sbom.utils.WebUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;

@Service
public class UvpClientImpl implements UvpClient {

    @Value("${uvp.api.url}")
    private String defaultBaseUrl;

    @Autowired
    private WebUtil webUtil;

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    @Override
    public Mono<UvpVulnerabilityReport[]> getComponentReport(List<String> coordinates) {
        WebClient client = webUtil.createWebClient(defaultBaseUrl);

        return client.post()
                .uri("/uvp-api/queryBatchV2")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(coordinates)
                .retrieve()
                .bodyToMono(UvpVulnerabilityReport[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }
}
