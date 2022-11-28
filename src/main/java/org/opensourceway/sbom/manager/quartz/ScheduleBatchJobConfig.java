package org.opensourceway.sbom.manager.quartz;

import org.quartz.CronScheduleBuilder;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ScheduleBatchJobConfig {

    @Bean
    public JobDetail readSbomJobDetail() {
        return JobBuilder.newJob(ReadSbomJob.class)
                .withIdentity("readSbom")
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger readSbomJobTrigger() {
        return TriggerBuilder.newTrigger()
                .forJob(readSbomJobDetail())
                .withIdentity("readSbom")
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule("0 * * * * ? *"))
                .build();
    }

    @Bean
    public JobDetail restartFailedReadJobDetail() {
        return JobBuilder.newJob(RestartFailedReadJob.class)
                .withIdentity("restartReadSbom")
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger restartFailedReadJobTrigger() {
        return TriggerBuilder.newTrigger()
                .forJob(restartFailedReadJobDetail())
                .withIdentity("restartReadSbom")
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule("30 0/5 * * * ? *"))
                .build();
    }

    @Bean
    public JobDetail fetchOpenEulerRepoMetaJobDetail() {
        return JobBuilder.newJob(FetchOpenEulerRepoMetaJob.class)
                .withIdentity("fetchOpenEulerRepoMeta")
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger fetchOpenEulerRepoMetaJobTrigger() {
        return TriggerBuilder.newTrigger()
                .forJob(fetchOpenEulerRepoMetaJobDetail())
                .withIdentity("fetchOpenEulerRepoMeta")
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule("0 31 14 ? * SAT *"))
                .build();
    }

    @Bean
    public JobDetail fetchOpenHarmonyRepoMetaJobDetail() {
        return JobBuilder.newJob(FetchOpenHarmonyRepoMetaJob.class)
                .withIdentity("fetchOpenHarmonyRepoMeta")
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger fetchOpenHarmonyRepoMetaJobTrigger() {
        return TriggerBuilder.newTrigger()
                .forJob(fetchOpenHarmonyRepoMetaJobDetail())
                .withIdentity("fetchOpenHarmonyRepoMeta")
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule("0 0 0 ? * SAT *"))
                .build();
    }

}
