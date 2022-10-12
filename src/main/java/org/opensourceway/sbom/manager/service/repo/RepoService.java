package org.opensourceway.sbom.manager.service.repo;

import org.opensourceway.sbom.openeuler.obs.vo.RepoInfoVo;

import java.io.IOException;
import java.util.Set;

public interface RepoService {

    Set<RepoInfoVo> fetchOpenEulerRepoMeta() throws IOException;
}