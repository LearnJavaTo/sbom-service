package org.opensourceway.sbom.batch.processor.vul;

import org.apache.commons.collections4.CollectionUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.vul.VulService;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ExtractUvpProcessor implements ItemProcessor<List<ExternalPurlRef>, Map<ExternalPurlRef, ?>>, StepExecutionListener {
    private static final Logger logger = LoggerFactory.getLogger(ExtractUvpProcessor.class);

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Autowired
    @Qualifier("uvpServiceImpl")
    private VulService uvpService;

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
    }

    @Nullable
    @Override
    public Map<ExternalPurlRef, ?> process(List<ExternalPurlRef> chunk) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractUvpProcessor sbomId:{}, chunk size:{}, first item id:{}",
                sbomId,
                chunk.size(),
                CollectionUtils.isEmpty(chunk) ? "" : chunk.get(0).getId().toString());

        var resultSet = uvpService.extractVulForPurlRefChunk(sbomId, chunk);

        logger.info("finish ExtractUvpProcessor sbomId:{}, resultSet size:{}", sbomId, resultSet.size());
        return resultSet;
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        return null;
    }

}
