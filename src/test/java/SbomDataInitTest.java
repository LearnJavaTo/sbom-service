import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.SbomManagerApplication;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.dao.FileRepository;
import org.opensourceway.sbom.dao.LicenseRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.ProductStatisticsRepository;
import org.opensourceway.sbom.dao.SbomElementRelationshipRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.dao.VulReferenceRepository;
import org.opensourceway.sbom.dao.VulScoreRepository;
import org.opensourceway.sbom.dao.VulnerabilityRepository;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgLicenseRelp;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductStatistics;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.entity.VulReference;
import org.opensourceway.sbom.model.entity.VulScore;
import org.opensourceway.sbom.model.entity.Vulnerability;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.enums.SbomFileType;
import org.opensourceway.sbom.model.enums.VulScoringSystem;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.opensourceway.sbom.utils.PurlUtil;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SbomDataInitTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulScoreRepository vulScoreRepository;

    @Autowired
    private VulReferenceRepository vulReferenceRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ProductStatisticsRepository productStatisticsRepository;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private FileRepository fileRepository;

    @Autowired
    private SbomElementRelationshipRepository elementRelationshipRepository;

    @Test
    @Order(1)
    public void uploadSbomFile() throws Exception {
        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME);
        MockMultipartFile file = new MockMultipartFile("uploadFileName", TestConstants.SAMPLE_UPLOAD_FILE_NAME
                , "json", classPathResource.getInputStream());

        this.mockMvc
                .perform(multipart("/sbom-api/uploadSbomFile").file(file)
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(content().string("Success"));
    }

    @Test
    @Order(2)
    public void insertVulnerability() {

        Vulnerability vul_2 = insertVulnerability("CVE-2022-00001-test");
        insertVulScore(vul_2, VulScoringSystem.CVSS_V2.name(), 9.8, "(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)");
        insertVulRef(vul_2, "ADVISORY", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00001-test");

        Vulnerability vul_1 = insertVulnerability("CVE-2022-00000-test");
        insertVulScore(vul_1, VulScoringSystem.CVSS_V3.name(), 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
        insertVulScore(vul_1, VulScoringSystem.CVSS_V2.name(), 7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P");
        insertVulRef(vul_1, "ADVISORY", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00000-test");
        insertVulRef(vul_1, "ADVISORY", "https://ossindex.sonatype.org/vulnerability/sonatype-2022-00000-test");

        Vulnerability vul_3 = insertVulnerability("CVE-2022-00002-test");
        insertVulRef(vul_3, "ADVISORY", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00002-test");
        insertVulRef(vul_3, "ADVISORY", "https://github.com/xxx/xxx/security/advisories/xxx");

        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        insertExternalVulRef(pkg, vul_1, "pkg:pypi/asttokens@2.0.5");
        insertExternalVulRef(pkg, vul_2, "pkg:pypi/asttokens@2.0.5");
        insertExternalVulRef(pkg, vul_3, "pkg:pypi/asttokens@2.0.5");
    }

    private Vulnerability insertVulnerability(String vulId) {
        Vulnerability existVulnerability = vulnerabilityRepository
                .findByVulId(vulId).orElse(null);
        if (Objects.nonNull(existVulnerability)) {
            vulnerabilityRepository.delete(existVulnerability);
        }

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulId(vulId);
        return vulnerabilityRepository.save(vulnerability);
    }

    private void insertVulScore(Vulnerability vul, String scoringSystem, Double score, String vector) {
        VulScore vulScore = new VulScore();
        vulScore.setScoringSystem(scoringSystem);
        vulScore.setScore(score);
        vulScore.setVector(vector);
        vulScore.setVulnerability(vul);
        vulScore.setSeverity(CvssSeverity.calculateCvssSeverity(VulScoringSystem.valueOf(scoringSystem), score).name());
        vulScoreRepository.save(vulScore);
    }

    private void insertVulRef(Vulnerability vul, String source, String url) {
        VulReference vulReference = new VulReference();
        vulReference.setType(source);
        vulReference.setUrl(url);
        vulReference.setVulnerability(vul);
        vulReferenceRepository.save(vulReference);
    }

    private void insertExternalVulRef(Package pkg, Vulnerability vul, String purl) {
        ExternalVulRef externalVulRef = new ExternalVulRef();
        externalVulRef.setPkg(pkg);
        externalVulRef.setVulnerability(vul);
        externalVulRef.setCategory("SECURITY");
        externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(purl));
        externalVulRefRepository.save(externalVulRef);
    }

    @Test
    @Order(3)
    public void insertLicenseAndCopyright() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();
        Package pkg1 = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-astunparse-1.6.3"))
                .findFirst().orElse(null);
        assertThat(pkg1).isNotNull();
        Map<String, License> existLicenses = licenseRepository.findAll().stream()
                .collect(Collectors.toMap(License::getSpdxLicenseId, Function.identity()));
        insertLicense("License-test", pkg, false, existLicenses);
        insertLicense("License-test1", pkg, true, existLicenses);
        insertLicense("License-test1", pkg1, true, existLicenses);
        insertCopyright(pkg);
        licenseRepository.saveAll(existLicenses.values());
        packageRepository.save(pkg);
        packageRepository.save(pkg1);
    }

    private void insertCopyright(Package pkg) {
        pkg.setCopyright("Copyright (c) 1989, 1991 Free Software Foundation, Inc.");
        assertThat(pkg.getCopyright()).isEqualTo("Copyright (c) 1989, 1991 Free Software Foundation, Inc.");
    }

    private void insertLicense(String lic, Package pkg, Boolean isLegal, Map<String, License> existLicenses) {
        License license = existLicenses.getOrDefault(lic, new License());
        existLicenses.put(lic, license);
        license.setSpdxLicenseId(lic);
        if (!pkg.containLicense(license)) {
            PkgLicenseRelp relp = new PkgLicenseRelp();
            relp.setLicense(license);
            relp.setPkg(pkg);
            pkg.addPkgLicenseRelp(relp);
            license.addPkgLicenseRelp(relp);
        }
        license.setName("License for test");
        license.setUrl("https://xxx/licenses/License-test");
        license.setIsLegal(isLegal);
    }

    @Test
    @Order(3)
    public void uploadOpenEulerSbomFile() throws Exception {
        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_REPODATA_SBOM_FILE_NAME);
        MockMultipartFile file = new MockMultipartFile("uploadFileName", TestConstants.SAMPLE_REPODATA_SBOM_FILE_NAME
                , "json", classPathResource.getInputStream());

        this.mockMvc
                .perform(multipart("/sbom-api/uploadSbomFile").file(file)
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(content().string("Success"));
    }

    @Test
    @Order(4)
    public void insertProductStatistics() {
        Product product = productRepository.findByName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(product).isNotNull();
        ProductStatistics statistics = productStatisticsRepository
                .findByProductNameAndCreateTime(TestConstants.SAMPLE_PRODUCT_NAME, new Timestamp((1663150600000L)))
                .orElse(new ProductStatistics());
        statistics.setProduct(product);
        statistics.setCreateTime(new Timestamp((1663150600000L)));
        statistics.setPackageCount(100L);
        statistics.setDepCount(200L);
        statistics.setModuleCount(300L);
        statistics.setRuntimeDepCount(0L);
        statistics.setVulCount(50L);
        statistics.setLicenseCount(60L);
        statistics.setCriticalVulCount(7L);
        statistics.setHighVulCount(8L);
        statistics.setMediumVulCount(9L);
        statistics.setLowVulCount(10L);
        statistics.setNoneVulCount(11L);
        statistics.setUnknownVulCount(5L);
        statistics.setPackageWithCriticalVulCount(13L);
        statistics.setPackageWithHighVulCount(14L);
        statistics.setPackageWithMediumVulCount(15L);
        statistics.setPackageWithLowVulCount(16L);
        statistics.setPackageWithNoneVulCount(17L);
        statistics.setPackageWithUnknownVulCount(18L);
        statistics.setPackageWithoutVulCount(7L);
        statistics.setPackageWithLegalLicenseCount(20L);
        statistics.setPackageWithIllegalLicenseCount(21L);
        statistics.setPackageWithoutLicenseCount(19L);
        statistics.setPackageWithMultiLicenseCount(10L);
        statistics.setLicenseDistribution(Map.of("Apache-2.0", 2L));

        ProductStatistics anotherStatistics = productStatisticsRepository
                .findByProductNameAndCreateTime(TestConstants.SAMPLE_PRODUCT_NAME, new Timestamp((1663250600000L)))
                .orElse(new ProductStatistics());
        anotherStatistics.setProduct(product);
        anotherStatistics.setCreateTime(new Timestamp((1663250600000L)));
        anotherStatistics.setPackageCount(1000L);
        anotherStatistics.setDepCount(2000L);
        anotherStatistics.setModuleCount(3000L);
        anotherStatistics.setRuntimeDepCount(0L);
        anotherStatistics.setVulCount(500L);
        anotherStatistics.setLicenseCount(600L);
        anotherStatistics.setCriticalVulCount(70L);
        anotherStatistics.setHighVulCount(80L);
        anotherStatistics.setMediumVulCount(90L);
        anotherStatistics.setLowVulCount(100L);
        anotherStatistics.setNoneVulCount(110L);
        anotherStatistics.setUnknownVulCount(50L);
        anotherStatistics.setPackageWithCriticalVulCount(130L);
        anotherStatistics.setPackageWithHighVulCount(140L);
        anotherStatistics.setPackageWithMediumVulCount(150L);
        anotherStatistics.setPackageWithLowVulCount(160L);
        anotherStatistics.setPackageWithNoneVulCount(170L);
        anotherStatistics.setPackageWithUnknownVulCount(180L);
        anotherStatistics.setPackageWithoutVulCount(70L);
        anotherStatistics.setPackageWithLegalLicenseCount(200L);
        anotherStatistics.setPackageWithIllegalLicenseCount(210L);
        anotherStatistics.setPackageWithoutLicenseCount(190L);
        anotherStatistics.setPackageWithMultiLicenseCount(100L);
        anotherStatistics.setLicenseDistribution(Map.of("MIT", 20L));

        product.setProductStatistics(List.of(statistics, anotherStatistics));
        productRepository.save(product);
    }

    @Test
    @Order(5)
    public void insertUpstreamAndPatchInfo() {
        Product product = productRepository.findByName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElse(null);
        assertThat(product).isNotNull();
        Optional<Sbom> sbomOptional = sbomRepository.findByProductName(product.getName());
        assertThat(sbomOptional.isPresent()).isTrue();
        Sbom sbom = sbomOptional.get();

        List<Package> pkgList = packageRepository.findBySbomIdAndSpdxId(sbom.getId(), "SPDXRef-rpm-hive-3.1.2");
        assertThat(CollectionUtils.isNotEmpty(pkgList)).isTrue();
        Package pkg = pkgList.get(0);

        fileRepository.deleteBySbomId(sbom.getId());
        File file = new File();
        file.setFileTypes(new String[]{SbomFileType.SOURCE.name()});
        file.setSbom(sbom);
        file.setSpdxId("hive-test1.patch");
        file.setFileName("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test1.patch");
        fileRepository.save(file);

        file = new File();
        file.setFileTypes(new String[]{SbomFileType.SOURCE.name()});
        file.setSbom(sbom);
        file.setSpdxId("hive-test2.patch");
        file.setFileName("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test2.patch");
        fileRepository.save(file);

        file = new File();
        file.setFileTypes(new String[]{SbomFileType.SOURCE.name()});
        file.setSbom(sbom);
        file.setSpdxId("hive-test3.patch");
        file.setFileName("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test3.patch");
        fileRepository.save(file);

        elementRelationshipRepository.deleteBySbomIdAndRelationshipType(sbom.getId(), RelationshipType.PATCH_APPLIED.name());
        SbomElementRelationship relationship = new SbomElementRelationship();
        relationship.setSbom(sbom);
        relationship.setRelationshipType(RelationshipType.PATCH_APPLIED.name());
        relationship.setRelatedElementId(pkg.getSpdxId());
        relationship.setElementId("hive-test1.patch");
        elementRelationshipRepository.save(relationship);

        relationship = new SbomElementRelationship();
        relationship.setSbom(sbom);
        relationship.setRelationshipType(RelationshipType.PATCH_APPLIED.name());
        relationship.setRelatedElementId(pkg.getSpdxId());
        relationship.setElementId("hive-test2.patch");
        elementRelationshipRepository.save(relationship);

        relationship = new SbomElementRelationship();
        relationship.setSbom(sbom);
        relationship.setRelationshipType(RelationshipType.PATCH_APPLIED.name());
        relationship.setRelatedElementId(pkg.getSpdxId());
        relationship.setElementId("hive-test3.patch");
        elementRelationshipRepository.save(relationship);

        externalPurlRefRepository.deleteByPkgIdAndCategory(pkg.getId(), ReferenceCategory.SOURCE_MANAGER.name());
        ExternalPurlRef upstream = new ExternalPurlRef();
        upstream.setPkg(pkg);
        upstream.setCategory(ReferenceCategory.SOURCE_MANAGER.name());
        upstream.setType(ReferenceType.URL.getType());
        upstream.setPurl(new PackageUrlVo("upstream", null, "http://hive.apache.org/", null));
        externalPurlRefRepository.save(upstream);

        upstream = new ExternalPurlRef();
        upstream.setPkg(pkg);
        upstream.setCategory(ReferenceCategory.SOURCE_MANAGER.name());
        upstream.setType(ReferenceType.URL.getType());
        upstream.setPurl(new PackageUrlVo("upstream", null, "https://gitee.com/src-openeuler/hive/tree/openEuler-22.03-LTS/", null));
        externalPurlRefRepository.save(upstream);
    }

}
