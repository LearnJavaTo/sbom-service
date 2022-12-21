package org.opensourceway.sbom.batch.reader.checksum;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.checksum.ChecksumService;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Sbom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ChunkListener;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.item.Chunk;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

public class PackageWithChecksumListReader implements ItemReader<Package>, StepExecutionListener, ChunkListener {

    private static final Logger logger = LoggerFactory.getLogger(PackageWithChecksumListReader.class);

    private final ChecksumService checksumService;

    @Autowired
    SbomRepository sbomRepository;

    private List<Package> chunks = null;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    private ChunkContext chunkContext;

    public PackageWithChecksumListReader(ChecksumService checksumService) {
        this.checksumService = checksumService;
    }

    public ChecksumService getChecksumService() {
        return checksumService;
    }

    private void initMapper(UUID sbomId) {
        if (!getChecksumService().needRequest()) {
            logger.warn("maven repo client does not request");
            return;
        }

        if (sbomId == null) {
            logger.warn("sbom id is mull");
            return;
        }
        Optional<Sbom> sbomOptional = sbomRepository.findById(sbomId);
        if (sbomOptional.isEmpty()) {
            logger.error("sbomId:{} is not exists", sbomId);
            return;
        }

        this.chunks = sbomOptional.get().getPackages()
                .stream()
                .filter(pkg -> pkg.getExternalPurlRefs()
                        .stream()
                        .anyMatch(externalPurlRef -> "checksum".equals(externalPurlRef.getType())))
                .collect(Collectors.toCollection(CopyOnWriteArrayList::new));// can't use unmodifiableList(can't remove)

        // restore chunks to previous operator, then partial retry
        int remainingSize = stepExecution.getExecutionContext().getInt(BatchContextConstants.BATCH_READER_STEP_REMAINING_SIZE_KEY, 0);
        if (remainingSize > 0 && remainingSize < this.chunks.size()) {
            this.chunks = this.chunks.subList(this.chunks.size() - remainingSize, this.chunks.size());
        }
        logger.info("PackageWithChecksumListReader:{} use sbomId:{}, get package chunks size:{}",
                this,
                sbomId,
                this.chunks.size());

    }

    @Nullable
    @Override
    public Package read() {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start PackageWithChecksumListReader sbomId:{}", sbomId);
        if (this.chunks == null) {
            initMapper(sbomId);
        }

        if (CollectionUtils.isEmpty(this.chunks)) {
            return null; // end of the chunks loops
        }
        return this.chunks.remove(0);
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        Assert.isTrue(this.stepExecution == null, "StepExecution is dirty");
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        int remainingSize = this.chunks.size();

        if (StringUtils.equals(ExitStatus.FAILED.getExitCode(), stepExecution.getExitStatus().getExitCode())
                && this.chunkContext.hasAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_KEY)
                && this.chunkContext.hasAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_INPUT_KEY)) {
            Chunk<Package> retryInputs = (Chunk<Package>) this.chunkContext.getAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_INPUT_KEY);
            assert retryInputs != null;
            remainingSize += CollectionUtils.size(retryInputs.getItems());
            logger.info("restore failed chunks, failed chunks size:{}, first element pkg id:{}",
                    retryInputs.getItems().size(),
                    retryInputs.getItems().get(0).getId());
        }

        stepExecution.getExecutionContext().putInt(BatchContextConstants.BATCH_READER_STEP_REMAINING_SIZE_KEY, remainingSize);
        return null;
    }

    @Override
    public void beforeChunk(@NotNull ChunkContext chunkContext) {
        if (this.chunkContext == null) {
            this.chunkContext = chunkContext;
        } else {
            Assert.isTrue(StringUtils.equals(this.chunkContext.getStepContext().getId(), chunkContext.getStepContext().getId()), "ChunkContext is dirty");
        }
    }

    @Override
    public void afterChunk(@NotNull ChunkContext chunkContext) {
    }

    @Override
    public void afterChunkError(@NotNull ChunkContext chunkContext) {
    }

}