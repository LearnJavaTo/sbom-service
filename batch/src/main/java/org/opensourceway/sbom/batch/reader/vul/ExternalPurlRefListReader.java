package org.opensourceway.sbom.batch.reader.vul;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.vul.VulService;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

public class ExternalPurlRefListReader implements ItemReader<List<ExternalPurlRef>>, StepExecutionListener, ChunkListener {

    private static final Logger logger = LoggerFactory.getLogger(ExternalPurlRefListReader.class);

    @Autowired
    private SbomRepository sbomRepository;

    private List<List<ExternalPurlRef>> chunks;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    private ChunkContext chunkContext;

    private final VulService vulService;

    public ExternalPurlRefListReader(VulService vulService) {
        this.vulService = vulService;
    }

    public VulService getVulService() {
        return vulService;
    }

    private void initMapper(UUID sbomId) {
        if (!getVulService().needRequest()) {
            logger.warn("vul client does not request");
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

        List<ExternalPurlRef> externalPurlRefs = sbomOptional.get().getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .filter(ref -> ReferenceCategory.COORDINATES_TYPE_NAME_LIST.contains(ref.getCategory()))
                .toList();

        this.chunks = ListUtils.partition(externalPurlRefs, getVulService().getBulkRequestSize())
                .stream()
                .map(ArrayList::new)// can't use ArrayList.subList(can't restart)
                .collect(Collectors.toCollection(CopyOnWriteArrayList::new));// can't use unmodifiableList(can't remove)

        // restore chunks to previous operator, then partial retry
        int remainingSize = stepExecution.getExecutionContext().getInt(BatchContextConstants.BATCH_READER_STEP_REMAINING_SIZE_KEY, 0);
        if (remainingSize > 0 && remainingSize < this.chunks.size()) {
            this.chunks = this.chunks.subList(this.chunks.size() - remainingSize, this.chunks.size());
        }

        logger.info("ExternalPurlRefListReader:{} use service name:{}, sbomId:{}, get externalPurlRefs size:{}, chunks size:{}",
                this,
                getVulService().getClass().getSimpleName(),
                sbomId,
                externalPurlRefs.size(),
                this.chunks.size());
    }

    @Nullable
    @Override
    public List<ExternalPurlRef> read() {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExternalPurlRefListReader service name:{}, sbomId:{}", getVulService().getClass().getSimpleName(), sbomId);
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
        if (this.chunks == null) {
            return null;
        }

        int remainingSize = this.chunks.size();

        if (StringUtils.equals(ExitStatus.FAILED.getExitCode(), stepExecution.getExitStatus().getExitCode())
                && this.chunkContext.hasAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_KEY)
                && this.chunkContext.hasAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_INPUT_KEY)) {
            Chunk<List<ExternalPurlRef>> retryInputs = (Chunk<List<ExternalPurlRef>>) this.chunkContext.getAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_INPUT_KEY);
            assert retryInputs != null;
            remainingSize += CollectionUtils.size(retryInputs.getItems());
            logger.info("restore failed chunks, job id:{}, remain chunk size:{}, failed chunks size:{}, first element pkg id:{}",
                    stepExecution.getJobExecution().getId(),
                    this.chunks.size(),
                    retryInputs.getItems().size(),
                    retryInputs.getItems().get(0).get(0).getPkg().getId());
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
