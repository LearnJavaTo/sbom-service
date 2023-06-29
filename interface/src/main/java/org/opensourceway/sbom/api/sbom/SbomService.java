package org.opensourceway.sbom.api.sbom;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.opensourceway.sbom.model.echarts.Graph;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductStatistics;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.pojo.request.sbom.AddProductRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.QuerySbomPackagesRequest;
import org.opensourceway.sbom.model.pojo.response.sbom.PublishResultResponse;
import org.opensourceway.sbom.model.pojo.vo.sbom.BinaryManagementVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.CopyrightVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.LicenseVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackagePurlVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageWithStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PageVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.ProductConfigVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulCountVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulnerabilityVo;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface SbomService {

    UUID publishSbom(PublishSbomRequest publishSbomRequest);

    PublishResultResponse getSbomPublishResult(UUID taskId);

    void readSbomFile(String productName, String fileName, byte[] fileContent) throws IOException;

    RawSbom writeSbomFile(String productName, String spec, String specVersion, String format);

    byte[] writeSbom(String productName, String spec, String specVersion, String format) throws IOException;

    PageVo<Package> findPackagesPageable(String productName, int page, int size);

    List<PackageWithStatisticsVo> queryPackageInfoByName(String productName, String packageName, boolean isExactly);

    Package queryPackageInfoById(String packageId);

    PageVo<PackageWithStatisticsVo> getPackageInfoByNameForPage(QuerySbomPackagesRequest req);

    BinaryManagementVo queryPackageBinaryManagement(String packageId, String binaryType);

    PageVo<PackagePurlVo> queryPackageInfoByBinaryViaSpec(ExternalPurlRefCondition condition, Pageable pageable);

    List<String> queryProductType();

    ProductConfigVo queryProductConfigByProductType(String productType);

    Product queryProductByFullAttributes(Map<String, String> attributes) throws JsonProcessingException;

    void persistSbomFromTraceData(String productName, String fileName, InputStream inputStream) throws IOException;

    ProductStatistics queryProductStatistics(String productName);

    List<VulCountVo> queryProductVulTrend(String productName, Long startTimestamp, Long endTimestamp);

    PackageStatisticsVo queryPackageStatisticsByPackageId(String packageId);

    List<LicenseVo> queryLicenseByPackageId(String packageId);

    PageVo<LicenseVo> queryLicense(String productName, String license, Boolean isLegal, Pageable pageable) throws Exception;

    List<CopyrightVo> queryCopyrightByPackageId(String packageId);

    PageVo<VulnerabilityVo> queryPackageVulnerability(String packageId, String severity, String vulId, Pageable pageable);

    PageVo<VulnerabilityVo> queryVulnerability(String productName, String packageId, String severity, String vulId, Pageable pageable);

    Graph queryVulImpact(String productName, String vulId);

    void addProduct(AddProductRequest req);

    byte[] writePackageSbom(String productName, String pkgName, String pkgVersion,
                            String spec, String specVersion, String format) throws IOException;

    byte[] writeAllPackageSbom(String productName, String spec, String specVersion, String format) throws IOException;
}
