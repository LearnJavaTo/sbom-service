package org.opensourceway.sbom.api.vul;

import org.opensourceway.sbom.model.entity.ExternalPurlRef;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface VulService {

    Integer getBulkRequestSize();

    boolean needRequest();

    Map<ExternalPurlRef, ?> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk);

    void persistExternalVulRefChunk(Map<ExternalPurlRef, ?> externalVulRefMap);
}
