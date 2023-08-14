package org.opensourceway.sbom.service.vul.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.api.vul.UvpClient;
import org.opensourceway.sbom.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.VulnerabilityRepository;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.VulReference;
import org.opensourceway.sbom.model.entity.VulScore;
import org.opensourceway.sbom.model.entity.Vulnerability;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.enums.VulScoringSystem;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.UvpVulnerability;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.UvpVulnerabilityReport;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.service.vul.AbstractVulService;
import org.opensourceway.sbom.utils.CvssUtil;
import org.opensourceway.sbom.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@Qualifier("uvpServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class UvpServiceImpl extends AbstractVulService {

    private static final Logger logger = LoggerFactory.getLogger(UvpServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 16;

    @Autowired
    private UvpClient uvpClient;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Override
    public Integer getBulkRequestSize() {
        return BULK_REQUEST_SIZE;
    }

    @Override
    public boolean needRequest() {
        return uvpClient.needRequest();
    }

    @Override
    public Map<ExternalPurlRef, List<UvpVulnerability>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk) {
        logger.info("Start to extract vulnerability from uvp for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Map<ExternalPurlRef, List<UvpVulnerability>> externalPurlRefMap = new HashMap<>();
        Map<ExternalPurlRef, Set<String>> externalPurlRefToVulIdMap = new HashMap<>();

        List<String> requestPurls = externalPurlChunk.stream()
                .map(ExternalPurlRef::getPurl)
                .map(this::enrichPurlForVulnMatch)
                .flatMap(List::stream)
                .distinct()
                .toList();

        ListUtils.partition(requestPurls, getBulkRequestSize()).forEach(requestPurlsChunk -> {
            try {
                UvpVulnerabilityReport[] response = uvpClient.getComponentReport(requestPurlsChunk).block();
                if (ObjectUtils.isEmpty(response)) {
                    return;
                }

                externalPurlChunk.forEach(purlRef -> Arrays.stream(response)
                        .filter(vulReport -> enrichPurlForVulnMatch(purlRef.getPurl()).contains(vulReport.getPurl()))
                        .filter(vulReport -> ObjectUtils.isNotEmpty(vulReport.getUvpVulnerabilities()))
                        .forEach(vulReport -> vulReport.getUvpVulnerabilities().stream()
                                .filter(vul -> Pattern.compile("^CVE-\\d+-\\d+$").matcher(vul.getId()).matches())
                                .forEach(vul -> {
                                    externalPurlRefMap.putIfAbsent(purlRef, new ArrayList<>());
                                    externalPurlRefToVulIdMap.putIfAbsent(purlRef, new HashSet<>());
                                    if (!externalPurlRefToVulIdMap.get(purlRef).contains(vul.getId())) {
                                        externalPurlRefMap.get(purlRef).add(vul);
                                        externalPurlRefToVulIdMap.get(purlRef).add(vul.getId());
                                    }
                                })));
            } catch (Exception e) {
                logger.error("failed to extract vulnerabilities from uvp for sbom {}", sbomId);
                reportVulFetchFailure(sbomId);
                throw e;
            }
        });

        return externalPurlRefMap;
    }

    private List<String> enrichPurlForVulnMatch(PackageUrlVo vo) {
        var purl = PurlUtil.packageUrlVoToPackageURL(vo);
        return List.of(PurlUtil.canonicalizePurl(purl), PurlUtil.canonicalizePurl(PurlUtil.convertPurlForVulnMatch(purl)));
    }

    @SuppressWarnings("unchecked")
    @Override
    public void persistExternalVulRefChunk(Map<ExternalPurlRef, ?> externalVulRefMap) {
        externalVulRefMap.forEach((purlRef, vuls) -> {
            Package purlOwnerPackage = packageRepository.findById(purlRef.getPkg().getId())
                    .orElseThrow(() -> new RuntimeException("package id: %s not found".formatted(purlRef.getPkg().getId())));
            Map<Pair<Vulnerability, String>, ExternalVulRef> existExternalVulRefs = Optional
                    .ofNullable(purlOwnerPackage.getExternalVulRefs())
                    .orElse(new ArrayList<>())
                    .stream()
                    .collect(Collectors.toMap(
                            it -> Pair.of(it.getVulnerability(), PurlUtil.canonicalizePurl(it.getPurl())),
                            Function.identity()));

            var uvpVuls = ((List<UvpVulnerability>) vuls);
            Map<String, Vulnerability> existVuls = vulnerabilityRepository
                    .findByVulIds(uvpVuls.stream().map(UvpVulnerability::getId).toList())
                    .stream()
                    .collect(Collectors.toMap(Vulnerability::getVulId, Function.identity()));

            uvpVuls.forEach(vul -> {
                Vulnerability vulnerability = persistVulnerability(vul, existVuls);
                existVuls.put(vul.getId(), vulnerability);

                ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(
                        Pair.of(vulnerability, PurlUtil.canonicalizePurl(purlRef.getPurl())), new ExternalVulRef());
                externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
                externalVulRef.setPurl(purlRef.getPurl());
                externalVulRef.setVulnerability(vulnerability);
                externalVulRef.setPkg(purlOwnerPackage);
                existExternalVulRefs.put(
                        Pair.of(vulnerability, PurlUtil.canonicalizePurl(purlRef.getPurl())), externalVulRef);
            });

            vulnerabilityRepository.saveAll(existVuls.values());
            externalVulRefRepository.saveAll(existExternalVulRefs.values());
        });
    }

    private Vulnerability persistVulnerability(UvpVulnerability uvpVulnerability, Map<String, Vulnerability> existVuls) {
        Vulnerability vulnerability = existVuls.getOrDefault(uvpVulnerability.getId(), new Vulnerability());
        vulnerability.setVulId(uvpVulnerability.getId());
        List<VulReference> vulReferences = persistVulReferences(vulnerability, uvpVulnerability);
        vulnerability.setVulReferences(vulReferences);
        vulnerability.setDescription(uvpVulnerability.getDetails());
        List<VulScore> vulScores = persistVulScores(vulnerability, uvpVulnerability);
        vulnerability.setVulScores(vulScores);
        return vulnerability;
    }

    private List<VulReference> persistVulReferences(Vulnerability vulnerability, UvpVulnerability uvpVulnerability) {
        List<VulReference> vulReferences = new ArrayList<>();
        if (ObjectUtils.isEmpty(uvpVulnerability.getReferences())) {
            return vulReferences;
        }

        Map<Pair<String, String>, VulReference> existVulReferences = Optional.ofNullable(vulnerability.getVulReferences())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getType(), it.getUrl()), Function.identity()));

        uvpVulnerability.getReferences().stream()
                .distinct()
                .forEach(reference -> {
                    VulReference vulReference = existVulReferences.getOrDefault(
                            Pair.of(reference.getType(), reference.getUrl()), new VulReference());
                    vulReference.setType(reference.getType());
                    vulReference.setUrl(reference.getUrl());
                    vulReference.setVulnerability(vulnerability);
                    vulReferences.add(vulReference);
                });

        return vulReferences;
    }

    private List<VulScore> persistVulScores(Vulnerability vulnerability, UvpVulnerability uvpVulnerability) {
        List<VulScore> vulScores = new ArrayList<>();
        if (ObjectUtils.isEmpty(uvpVulnerability.getSeverities())) {
            return vulScores;
        }

        Map<Pair<String, String>, VulScore> existVulScores = Optional.ofNullable(vulnerability.getVulScores())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getScoringSystem(), it.getVector()), Function.identity()));

        uvpVulnerability.getSeverities().stream()
                .distinct()
                .forEach(severity -> {
                    String vector = severity.getScore();
                    Double score = CvssUtil.calculateScore(vector);
                    VulScoringSystem vulScoringSystem = VulScoringSystem.findVulScoringSystemByName(severity.getType());
                    VulScore vulScore = existVulScores.getOrDefault(Pair.of(vulScoringSystem.name(), vector), new VulScore());
                    vulScore.setScoringSystem(vulScoringSystem.name());
                    vulScore.setScore(score);
                    vulScore.setVector(vector);
                    vulScore.setVulnerability(vulnerability);
                    vulScore.setSeverity(CvssSeverity.calculateCvssSeverity(vulScoringSystem, score).name());
                    vulScores.add(vulScore);
                });

        return vulScores;
    }
}
