package org.opensourceway.sbom.batch.writer.vul;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.vul.VulService;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ChunkListener;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ExternalPurlRefListWriter implements ItemWriter<Map<ExternalPurlRef, ?>>, StepExecutionListener, ChunkListener {

    private static final Logger logger = LoggerFactory.getLogger(ExternalPurlRefListWriter.class);

    private final VulService vulService;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    public ExternalPurlRefListWriter(VulService vulService) {
        this.vulService = vulService;
    }

    public VulService getVulService() {
        return vulService;
    }

    @Override
    public void write(List<? extends Map<ExternalPurlRef, ?>> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExternalPurlRefListWriter service name:{}, sbomId:{}, chunk size:{}",
                getVulService().getClass().getSimpleName(), sbomId, chunks.size());
        chunks.forEach(chunk -> getVulService().persistExternalVulRefChunk(chunk));
        logger.info("finish ExternalPurlRefListWriter sbomId:{}", sbomId);
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        return null;
    }

    @Override
    public void beforeChunk(@NotNull ChunkContext context) {
    }

    @Override
    public void afterChunk(@NotNull ChunkContext context) {
    }

    @Override
    public void afterChunkError(ChunkContext context) {
        Map<String, Object> jobExecutionContext = context.getStepContext().getJobExecutionContext();
        UUID sbomId = jobExecutionContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) jobExecutionContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;

        logger.info("ExternalPurlRefListWriter failed, service name:{}, sbomId:{}, ", getVulService().getClass().getSimpleName(), sbomId);
    }

}
