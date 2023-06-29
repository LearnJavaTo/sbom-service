package org.opensourceway.sbom.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.github.packageurl.PackageURL;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.pojo.vo.repo.ThirdPartyMetaVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
public class OpenHarmonyThirdPartyUtil {

    private static final Logger logger = LoggerFactory.getLogger(OpenHarmonyThirdPartyUtil.class);

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Value("${gitee.domain.url}")
    private String giteeDomainUrl;

    public List<ThirdPartyMetaVo> getThirdPartyMeta(String purl) {
        PackageURL packageURL = PurlUtil.newPackageURL(purl);
        if (!packageURL.getName().startsWith(SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_REPO_PREFIX)) {
            return null;
        }

        try {
            String thirdPartyMetaUrl = MessageFormat.format("{0}/{1}/{2}/raw/{3}/{4}",
                    giteeDomainUrl, SbomRepoConstants.OPEN_HARMONY_GITEE_ORG, packageURL.getName(),
                    Optional.ofNullable(packageURL.getQualifiers()).orElse(Map.of())
                            .getOrDefault(SbomRepoConstants.OPEN_HARMONY_PURL_QUALIFIER_REVISION, packageURL.getVersion()),
                    SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_META_FILE);
            String thirdPartyMeta = giteeApi.getFileContext(thirdPartyMetaUrl);
            return Mapper.jsonMapper.readValue(thirdPartyMeta, new TypeReference<>() {
            });
        } catch (Exception e) {
            logger.warn("Unknown exception occurs when fetch repo meta for purl: {}", purl, e);
            return null;
        }
    }
}
