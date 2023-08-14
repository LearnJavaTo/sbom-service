package org.opensourceway.sbom.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.api.license.LicenseService;
import org.opensourceway.sbom.api.sbom.SbomService;
import org.opensourceway.sbom.cache.LicenseInfoMapCache;
import org.opensourceway.sbom.cache.LicenseStandardMapCache;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.LicenseRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.ProductTypeRepository;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductType;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.enums.SbomContentType;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;
import org.opensourceway.sbom.model.pojo.response.license.ComplianceResponse;
import org.opensourceway.sbom.model.pojo.response.sbom.PublishResultResponse;
import org.opensourceway.sbom.model.pojo.vo.sbom.BinaryManagementVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackagePurlVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageWithStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PageVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.ProductConfigVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulnerabilityVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.opensourceway.sbom.utils.TestCommon;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SbomServiceTest {

    @Autowired
    private SbomService sbomService;

    @Autowired
    private ProductTypeRepository productTypeRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private RawSbomRepository rawSbomRepository;

    @Autowired
    private TestCommon testCommon;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private LicenseService licenseService;

    @Autowired
    private LicenseClient licenseClient;

    @Autowired
    private LicenseStandardMapCache licenseStandardMapCache;

    @Autowired
    private LicenseInfoMapCache licenseInfoMapCache;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    private static String packageId = null;

    private void getPackageId() {
        if (SbomServiceTest.packageId != null) {
            return;
        }

        List<PackageWithStatisticsVo> packagesList = sbomService.queryPackageInfoByName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME, TestConstants.BINARY_TEST_PACKAGE_NAME, true);
        assertThat(packagesList).isNotEmpty();

        SbomServiceTest.packageId = packagesList.get(0).getId().toString();
    }

    @Test
    public void getAllCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, null);
        assertThat(vo.getPackageList().size()).isEqualTo(1);
        assertThat(vo.getProvideList().size()).isEqualTo(36);
        assertThat(vo.getExternalList().size()).isEqualTo(216);
        assertThat(vo.getRelationshipList().size()).isEqualTo(4);
    }

    @Test
    public void getPackageCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.PACKAGE_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(1);
        assertThat(vo.getProvideList().size()).isEqualTo(0);
        assertThat(vo.getExternalList().size()).isEqualTo(0);
        assertThat(vo.getRelationshipList().size()).isEqualTo(0);
    }

    @Test
    public void getProvideCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.PROVIDE_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isEqualTo(36);
        assertThat(vo.getExternalList().size()).isEqualTo(0);
        assertThat(vo.getRelationshipList().size()).isEqualTo(0);
    }

    @Test
    public void getExternalCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.EXTERNAL_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isEqualTo(0);
        assertThat(vo.getExternalList().size()).isEqualTo(216);
        assertThat(vo.getRelationshipList().size()).isEqualTo(0);
    }

    @Test
    public void getRelationshipRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.RELATIONSHIP_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isEqualTo(0);
        assertThat(vo.getExternalList().size()).isEqualTo(0);
        assertThat(vo.getRelationshipList().size()).isEqualTo(4);
    }

    @Test
    public void queryPackageInfoByBinaryExactlyTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .binaryType(ReferenceCategory.EXTERNAL_MANAGER.name())
                .type("maven")
                .namespace("org.apache.zookeeper")
                .name("zookeeper")
                .version("3.4.6")
                .build();
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(condition, pageable);
        assertThat(result.getTotalElements()).isEqualTo(1);
    }

    @Test
    public void queryPackageInfoByBinaryWithoutVersionTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .binaryType(ReferenceCategory.EXTERNAL_MANAGER.name())
                .type("maven")
                .namespace("org.apache.zookeeper")
                .name("zookeeper")
                .version("")
                .build();
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(condition, pageable);
        assertThat(result.getTotalElements()).isEqualTo(7);
    }

    @Test
    public void queryPackageInfoByBinaryOnlyNameTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .binaryType(ReferenceCategory.EXTERNAL_MANAGER.name())
                .type("maven")
                .namespace("")
                .name("zookeeper")
                .version("")
                .build();
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(condition, pageable);
        assertThat(result.getTotalElements()).isEqualTo(9);
    }

    @Test
    public void queryPackageInfoByBinaryChecksumTest() {
        // use checksum type, to:pkg:maven/sha1/2a2d713f56de83f4e84fab07a7edfbfcebf403af@1.0.0
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .binaryType(ReferenceCategory.EXTERNAL_MANAGER.name())
                .type("maven")
                .namespace("sqlline")
                .name("zookeeper")
                .version("1.3.0")
                .build();
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(condition, pageable);
        assertThat(result.getTotalElements()).isEqualTo(0);
    }

    @Test
    public void queryPackageInfoByBinaryChecksumTest1() {
        // actual purl value: pkg:maven/sqlline/sqlline@1.3.0
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .binaryType(ReferenceCategory.EXTERNAL_MANAGER.name())
                .type("maven")
                .namespace("sha1")
                .name("2a2d713f56de83f4e84fab07a7edfbfcebf403af")
                .version("1.0.0")
                .build();
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(condition, pageable);
        assertThat(result.getTotalElements()).isEqualTo(0);
    }

    @Test
    public void queryPackageInfoByBinaryViaSpecFullComponent() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_PRODUCT_NAME)
                .binaryType(ReferenceCategory.PACKAGE_MANAGER.name())
                .type("gitee")
                .namespace("mindspore")
                .name("akg")
                .version("1.7.0")
                .build();

        PageVo<PackagePurlVo> refs = sbomService.queryPackageInfoByBinaryViaSpec(condition, PageRequest.of(0, 15));
        assertThat(refs.getTotalElements()).isEqualTo(1);
    }

    @Test
    public void queryPackageInfoByBinaryViaSpecNotExists() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_PRODUCT_NAME)
                .binaryType(ReferenceCategory.PACKAGE_MANAGER.name())
                .type("gitee")
                .namespace("mindspore")
                .name("akg")
                .version("x.7.0")
                .build();

        PageVo<PackagePurlVo> refs = sbomService.queryPackageInfoByBinaryViaSpec(condition, PageRequest.of(0, 15));
        assertThat(refs.getTotalElements()).isEqualTo(0);
    }

    @Test
    public void queryProductType() {
        ProductType productType = new ProductType();
        productType.setType("test_type_1");
        productType.setActive(true);
        ProductType ret = productTypeRepository.save(productType);

        List<String> productTypes = sbomService.queryProductType();
        assertThat(productTypes.contains("test_type_1")).isTrue();

        productTypeRepository.delete(ret);
    }

    @Test
    public void queryProductConfigByProductType() {
        ProductConfigVo configVos = sbomService.queryProductConfigByProductType(TestConstants.TEST_PRODUCT_TYPE);
        assertThat(configVos.getName()).isEqualTo("arg");
        assertThat(configVos.getLabel()).isEqualTo("测试参数");
        assertThat(configVos.getValueToNextConfig().size()).isGreaterThan(0);
    }

    @Test
    public void queryProductByFullAttributes() throws JsonProcessingException {
        Product product = new Product();
        product.setName("test_product");
        product.setAttribute(Map.of("os", "linux", "arch", "x86_64", "test", "1"));
        Product ret = productRepository.save(product);

        Product product_found = sbomService.queryProductByFullAttributes(Map.of("os", "linux", "arch", "x86_64", "test", "1"));
        assertThat(product_found.getName()).isEqualTo("test_product");
        assertThat(product_found.getAttribute().get("os")).isEqualTo("linux");
        assertThat(product_found.getAttribute().get("arch")).isEqualTo("x86_64");
        assertThat(product_found.getAttribute().get("test")).isEqualTo("1");

        productRepository.delete(ret);
    }

    @Test
    public void queryPackageVulnerability() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryPackageVulnerability(
                pkg.getId().toString(), null, null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(3);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(1), "pkg:pypi/asttokens@2.0.5");
        assertVulWithHighSeverity(result.getContent().get(0), "pkg:pypi/asttokens@2.0.5");
        assertVulWithUnknownSeverity(result.getContent().get(2), "pkg:pypi/asttokens@2.0.5");
    }

    @Test
    public void queryPackageVulnerabilityWithSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryPackageVulnerability(
                pkg.getId().toString(), "MEDIUM", null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(0), "pkg:pypi/asttokens@2.0.5");
    }

    @Test
    public void queryPackageVulnerabilityWithVulId() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryPackageVulnerability(
                pkg.getId().toString(), null, "CVE-2022-00000-test", PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(0), "pkg:pypi/asttokens@2.0.5");
    }

    @Test
    public void queryVulnerabilityByPackageId() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), null, null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(3);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(1));
        assertVulWithHighSeverity(result.getContent().get(0));
        assertVulWithUnknownSeverity(result.getContent().get(2));
    }

    @Test
    public void queryVulnerabilityByPackageIdAndHighSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), CvssSeverity.HIGH.name(), null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithHighSeverity(result.getContent().get(0));
    }

    @Test
    public void queryVulnerabilityByPackageIdAndMediumSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), CvssSeverity.MEDIUM.name(), null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(0));
    }

    @Test
    public void queryVulnerabilityByPackageIdAndUnknownSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), CvssSeverity.UNKNOWN.name(), null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithUnknownSeverity(result.getContent().get(0));
    }

    @Test
    public void queryVulnerabilityByPackageIdAndLowSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), CvssSeverity.LOW.name(), null, PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
    }

    @Test
    public void queryVulnerabilityByPackageIdAndNoneSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), CvssSeverity.NONE.name(), null, PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
    }

    @Test
    public void queryVulnerabilityByPackageIdAndCriticalSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, pkg.getId().toString(), CvssSeverity.CRITICAL.name(), null, PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
    }

    @Test
    public void queryVulnerabilityByProductName() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, null, null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(3);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(1));
        assertVulWithHighSeverity(result.getContent().get(0));
        assertVulWithUnknownSeverity(result.getContent().get(2));
    }

    @Test
    public void queryVulnerabilityByProductNameAndHighSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, CvssSeverity.HIGH.name(), null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithHighSeverity(result.getContent().get(0));
    }

    @Test
    public void queryVulnerabilityByProductNameAndMediumSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, CvssSeverity.MEDIUM.name(), null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithMediumSeverity(result.getContent().get(0));
    }

    @Test
    public void queryVulnerabilityByProductNameAndUnknownSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, CvssSeverity.UNKNOWN.name(), null, PageRequest.of(0, 15));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertVulWithUnknownSeverity(result.getContent().get(0));
    }

    @Test
    public void queryVulnerabilityByProductNameAndLowSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, CvssSeverity.LOW.name(), null, PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
    }

    @Test
    public void queryVulnerabilityByProductNameAndNoneSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, CvssSeverity.NONE.name(), null, PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
    }

    @Test
    public void queryVulnerabilityByProductNameAndCriticalSeverity() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, CvssSeverity.CRITICAL.name(), null, PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
    }

    @Test
    public void queryVulnerabilityByProductNameAndVulId() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerability(
                TestConstants.SAMPLE_PRODUCT_NAME, null, null, "CVE-2022-00000-test", PageRequest.of(0, 15));
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getTotalPages()).isEqualTo(1);
    }

    private void assertVulWithMediumSeverity(VulnerabilityVo vo, String expectedPurl) {
        assertThat(vo.getVulId()).isEqualTo("CVE-2022-00000-test");
        assertThat(vo.getScoringSystem()).isEqualTo("CVSS_V3");
        assertThat(vo.getScore()).isEqualTo(5.3);
        assertThat(vo.getVector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
        assertThat(vo.getSeverity()).isEqualTo(CvssSeverity.MEDIUM.name());
        if (expectedPurl != null) {
            assertThat(vo.getPurl()).isEqualTo(expectedPurl);
        } else {
            assertThat(vo.getPurl()).isNull();
        }
        assertThat(vo.getReferences().size()).isEqualTo(2);
        assertThat(vo.getReferences().get(0).getFirst()).isEqualTo("ADVISORY");
        assertThat(vo.getReferences().get(0).getSecond()).isEqualTo("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00000-test");
        assertThat(vo.getReferences().get(1).getFirst()).isEqualTo("ADVISORY");
        assertThat(vo.getReferences().get(1).getSecond()).isEqualTo("https://ossindex.sonatype.org/vulnerability/sonatype-2022-00000-test");
    }

    private void assertVulWithMediumSeverity(VulnerabilityVo vo) {
        assertVulWithMediumSeverity(vo, null);
    }

    private void assertVulWithHighSeverity(VulnerabilityVo vo, String expectedPurl) {
        assertThat(vo.getVulId()).isEqualTo("CVE-2022-00001-test");
        assertThat(vo.getScoringSystem()).isEqualTo("CVSS_V2");
        assertThat(vo.getScore()).isEqualTo(9.8);
        assertThat(vo.getVector()).isEqualTo("(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)");
        assertThat(vo.getSeverity()).isEqualTo(CvssSeverity.HIGH.name());
        if (expectedPurl != null) {
            assertThat(vo.getPurl()).isEqualTo(expectedPurl);
        } else {
            assertThat(vo.getPurl()).isNull();
        }
        assertThat(vo.getReferences().size()).isEqualTo(1);
        assertThat(vo.getReferences().get(0).getFirst()).isEqualTo("ADVISORY");
        assertThat(vo.getReferences().get(0).getSecond()).isEqualTo("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00001-test");
    }

    private void assertVulWithHighSeverity(VulnerabilityVo vo) {
        assertVulWithHighSeverity(vo, null);
    }

    private void assertVulWithUnknownSeverity(VulnerabilityVo vo, String expectedPurl) {
        assertThat(vo.getVulId()).isEqualTo("CVE-2022-00002-test");
        assertThat(vo.getScoringSystem()).isNull();
        assertThat(vo.getScore()).isNull();
        assertThat(vo.getVector()).isNull();
        assertThat(vo.getSeverity()).isEqualTo(CvssSeverity.UNKNOWN.name());
        if (expectedPurl != null) {
            assertThat(vo.getPurl()).isEqualTo(expectedPurl);
        } else {
            assertThat(vo.getPurl()).isNull();
        }
        assertThat(vo.getReferences().size()).isEqualTo(2);
        assertThat(vo.getReferences().get(0).getFirst()).isEqualTo("ADVISORY");
        assertThat(vo.getReferences().get(0).getSecond()).isEqualTo("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00002-test");
        assertThat(vo.getReferences().get(1).getFirst()).isEqualTo("ADVISORY");
        assertThat(vo.getReferences().get(1).getSecond()).isEqualTo("https://github.com/xxx/xxx/security/advisories/xxx");
    }

    private void assertVulWithUnknownSeverity(VulnerabilityVo vo) {
        assertVulWithUnknownSeverity(vo, null);
    }

    @Test
    public void queryLicenseByPackageId() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();
        List<License> licenses = licenseRepository.findByPkgId(pkg.getId());
        assertThat(licenses.size()).isEqualTo(2);
        assertThat(licenses.get(0).getSpdxLicenseId()).isEqualTo("License-test");
        assertThat(licenses.get(0).getName()).isEqualTo("License for test");
        assertThat(licenses.get(0).getUrl()).isEqualTo("https://xxx/licenses/License-test");
        assertThat(licenses.get(0).getIsLegal()).isEqualTo(false);
    }

    @Test
    public void queryLicenseAndCopyrightByPurl() throws JsonProcessingException {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Product product = productRepository.findBySbomId(sbom.getId());
        assertThat(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY)).isEqualTo("openEuler-22.03-LTS");
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-eb661a27c2fb073c"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();
        ExternalPurlRef externalPurlRef = pkg.getExternalPurlRefs().get(0);
        String purl = licenseService.getPurlsForLicense(externalPurlRef.getPurl(), product);
        assertThat(purl).isEqualTo("pkg:gitee/src-openeuler/capstone@openEuler-22.03-LTS");
        ComplianceResponse[] responseArr = licenseClient.getComplianceResponse(List.of(purl));
        assertThat(responseArr.length).isEqualTo(1);
        assertThat(responseArr[0].getPurl()).isEqualTo(purl);
        assertThat(responseArr[0].getResult().getIsSca()).isEqualTo("true");

        Package pkg1 = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-rpm-hadoop-3.1-common-3.1.4"))
                .findFirst().orElse(null);
        assertThat(pkg1).isNotNull();
        ExternalPurlRef externalPurlRef1 = pkg1.getExternalPurlRefs().get(0);
        String purl1 = licenseService.getPurlsForLicense(externalPurlRef1.getPurl(), product);
        List<RepoMeta> repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(SbomConstants.PRODUCT_OPENEULER_NAME,
                product.getProductVersion(), externalPurlRef1.getPurl().getName());
        if (!ObjectUtils.isEmpty(repoMetaList) && !repoMetaList.get(0).getDownloadLocation().isEmpty()) {
            assertThat(purl1).isEqualTo("pkg:gitee/src-openeuler/hadoop-3.1@openEuler-22.03-LTS");
        } else {
            assertThat(purl1).isEqualTo("pkg:gitee/src-openeuler/hadoop-3.1-common@openEuler-22.03-LTS");
        }
        ComplianceResponse[] responseArr1 = licenseClient.getComplianceResponse(List.of(purl));
        assertThat(responseArr1.length).isEqualTo(1);
        assertThat(responseArr1[0].getPurl()).isEqualTo(purl);
        assertThat(responseArr1[0].getResult().getIsSca()).isEqualTo("true");
    }

    @Test
    public void persistSbomFromTraceData() throws IOException {

        sbomService.persistSbomFromTraceData(
                TestConstants.SAMPLE_MINDSPORE_TRACER_PRODUCT_NAME,
                TestConstants.SAMPLE_UPLOAD_TRACE_DATA_NAME,
                new ClassPathResource(TestConstants.SAMPLE_UPLOAD_TRACE_DATA_NAME).getInputStream());

        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_MINDSPORE_TRACER_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        assertThat(sbom.getName()).isEqualTo("mindsporeTracerTest");

        List<Package> packages = sbom.getPackages();
        assertThat(packages.size()).isEqualTo(2);

        Package akg = packages.stream().filter(p -> StringUtils.equals(p.getName(), "akg")).findFirst().orElse(null);
        assertThat(akg).isNotNull();
        assertThat(akg.getSpdxId()).isEqualTo("SPDXRef-Package-gitee-mindspore-akg-v1.7.0");
        assertThat(akg.getVersion()).isEqualTo("v1.7.0");

        Package protobuf = packages.stream().filter(p -> StringUtils.equals(p.getName(), "protobuf")).findFirst().orElse(null);
        assertThat(protobuf).isNotNull();
        assertThat(protobuf.getSpdxId()).isEqualTo("SPDXRef-Package-github-protocolbuffers-protobuf-v3.13.0");
        assertThat(protobuf.getVersion()).isEqualTo("v3.13.0");
    }


    @Test
    @Order(1)
    public void republishWaitingSbom() throws IOException {
        testCommon.cleanPublishRawSbomData(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);

        PublishSbomRequest request = new PublishSbomRequest();
        request.setProductName(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);
        request.setSbomContentType(SbomContentType.SPDX_2_2_JSON_SBOM.getType());
        request.setSbomContent(IOUtils.toString(new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME).getInputStream(), Charset.defaultCharset()));

        UUID taskId = sbomService.publishSbom(request);
        PublishResultResponse response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        String errorMsg = null;
        try {
            sbomService.publishSbom(request);
        } catch (RuntimeException e) {
            errorMsg = e.getMessage();
        }
        assertThat(errorMsg).isEqualTo("product: %s has sbom import job in running.".formatted(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME));

        RawSbom rawSbom = rawSbomRepository.findByTaskId(taskId).orElse(null);
        if (Objects.nonNull(rawSbom)) {
            rawSbomRepository.delete(rawSbom);
        }
    }

    @Test
    @Order(2)
    public void republishFinishedSbom() throws IOException {
        testCommon.cleanPublishRawSbomData(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);

        PublishSbomRequest request = new PublishSbomRequest();
        request.setProductName(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);
        request.setSbomContentType(SbomContentType.SPDX_2_2_JSON_SBOM.getType());
        request.setSbomContent(IOUtils.toString(new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME).getInputStream(), Charset.defaultCharset()));

        UUID taskId = sbomService.publishSbom(request);
        PublishResultResponse response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        RawSbom rawSbom = rawSbomRepository.findByTaskId(taskId).orElseThrow(() -> new RuntimeException(""));
        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_FINISH);
        rawSbomRepository.save(rawSbom);
        response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).contains(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);
        assertThat(response.getFinish()).isTrue();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        UUID taskIdRepublish = sbomService.publishSbom(request);
        assertThat(taskId).isNotEqualTo(taskIdRepublish);
        response = sbomService.getSbomPublishResult(taskIdRepublish);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        RawSbom rawSbomDelete = rawSbomRepository.findByTaskId(taskIdRepublish).orElse(null);
        if (Objects.nonNull(rawSbomDelete)) {
            rawSbomRepository.delete(rawSbomDelete);
        }
    }

    @Test
    @Order(3)
    public void getSbomPublishResultNotExist() {
        PublishResultResponse response = sbomService.getSbomPublishResult(UUID.fromString("12341234-1234-1234-1234-123412341234"));
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isEqualTo(SbomConstants.TASK_STATUS_NOT_EXISTS);
        assertThat(response.getSuccess()).isFalse();
    }

    @Test
    public void getStandardLicense() {
        String license1 = "license-test";
        assertThat(licenseStandardMapCache.getLicenseStandardMap(CacheConstants.LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN)
                .getOrDefault(license1.toLowerCase(), license1)).isEqualTo("license-test");
        String license2 = "agpl-3.0+";
        assertThat(licenseStandardMapCache.getLicenseStandardMap(CacheConstants.LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN)
                .getOrDefault(license2.toLowerCase(), license2)).isEqualTo("AGPL-3.0-or-later");
        String license3 = "AGPL-3.0+";
        assertThat(licenseStandardMapCache.getLicenseStandardMap(CacheConstants.LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN)
                .getOrDefault(license3.toLowerCase(), license3)).isEqualTo("AGPL-3.0-or-later");
    }
}
