package org.opensourceway.sbom.batch.step;

import com.github.packageurl.PackageURL;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.batch.utils.ExecutionContextUtils;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spdx.SpdxDocument;
import org.opensourceway.sbom.model.spdx.SpdxExternalReference;
import org.opensourceway.sbom.model.spdx.SpdxPackage;
import org.opensourceway.sbom.utils.OpenHarmonyThirdPartyUtil;
import org.opensourceway.sbom.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ObjectUtils;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public class OpenHarmonySpecialTaskStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(OpenHarmonySpecialTaskStep.class);

    @Autowired
    private OpenHarmonyThirdPartyUtil openHarmonyThirdPartyUtil;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) throws Exception {
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        logger.info("start OpenHarmonySpecialTaskStep rawSbomId: {}, productName: {}", rawSbomId, productName);

        var sbomDocument = (SpdxDocument) jobContext.get(BatchContextConstants.BATCH_SBOM_DOCUMENT_KEY);
        Optional.ofNullable(sbomDocument)
                .flatMap(it -> Optional.ofNullable(it.getPackages()))
                .ifPresent(it -> it.stream().filter(Objects::nonNull).forEach(this::fulfillThirdPartyDependencies));
        jobContext.put(BatchContextConstants.BATCH_SBOM_DOCUMENT_KEY, sbomDocument);

        logger.info("finish OpenHarmonySpecialTaskStep rawSbomId: {}, productName: {}", rawSbomId, productName);
        return RepeatStatus.FINISHED;
    }

    private void fulfillThirdPartyDependencies(SpdxPackage pkg) {
        if (Objects.isNull(pkg.getExternalRefs())) {
            return;
        }

        var ref = pkg.getExternalRefs().stream()
                .filter(it -> ReferenceCategory.PACKAGE_MANAGER.equals(it.referenceCategory()))
                .findFirst().orElse(null);
        if (Objects.isNull(ref)) {
            return;
        }

        PackageURL packageURL = PurlUtil.newPackageURL(ref.referenceLocator());
        if (!packageURL.getName().startsWith(SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_REPO_PREFIX)) {
            return;
        }

        var metas = openHarmonyThirdPartyUtil.getThirdPartyMeta(ref.referenceLocator());
        if (ObjectUtils.isEmpty(metas)) {
            return;
        }

        metas.stream().filter(Objects::nonNull).forEach(meta -> {
            var thirdPartyPurl = SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_PURL_PATTERN.formatted(
                    meta.getName().strip(), meta.getVersion().strip(), meta.getUpstreamUrl().strip());
            var provide = new SpdxExternalReference(null, ReferenceCategory.PROVIDE_MANAGER,
                    ReferenceType.PURL, thirdPartyPurl);
            if (!pkg.getExternalRefs().contains(provide)) {
                pkg.getExternalRefs().add(provide);
            }
        });
    }
}
