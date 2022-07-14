package org.openeuler.sbom.manager.service;


import org.junit.jupiter.api.Test;
import org.openeuler.sbom.manager.TestConstants;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.spdx.ReferenceCategory;
import org.openeuler.sbom.manager.model.vo.BinaryManagementVo;
import org.openeuler.sbom.manager.model.vo.PackagePurlVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class SbomServiceTest {


    @Autowired
    private SbomService sbomService;

    private static String packageId = null;

    private void getPackageId() {
        if (SbomServiceTest.packageId != null) {
            return;
        }

        List<Package> packagesList = sbomService.queryPackageInfoByName(TestConstants.OPENEULER_PRODUCT_NAME, TestConstants.BINARY_TEST_PACKAGE_NAME, true);
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
        assertThat(vo.getProvideList().size()).isGreaterThan(1);
        assertThat(vo.getExternalList().size()).isGreaterThan(1);
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
    }

    @Test
    public void getProvideCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.PROVIDE_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isGreaterThan(1);
        assertThat(vo.getExternalList().size()).isEqualTo(0);
    }

    @Test
    public void getExternalCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.EXTERNAL_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isEqualTo(0);
        assertThat(vo.getExternalList().size()).isGreaterThan(1);
    }


    @Test
    public void queryPackageInfoByBinaryExactlyTest() throws Exception {
        List<PackagePurlVo> result = sbomService.queryPackageInfoByBinary(TestConstants.OPENEULER_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                "maven",
                "org.apache.zookeeper",
                "zookeeper",
                "3.4.6");
        assertThat(result.size()).isEqualTo(1);
    }

    @Test
    public void queryPackageInfoByBinaryWithoutVersionTest() throws Exception {
        List<PackagePurlVo> result = sbomService.queryPackageInfoByBinary(TestConstants.OPENEULER_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                "maven",
                "org.apache.zookeeper",
                "zookeeper",
                "");
        assertThat(result.size()).isEqualTo(10);
    }

    @Test
    public void queryPackageInfoByBinaryOnlyNameTest() throws Exception {
        List<PackagePurlVo> result = sbomService.queryPackageInfoByBinary(TestConstants.OPENEULER_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                "maven",
                "",
                "zookeeper",
                "");
        assertThat(result.size()).isEqualTo(12);
    }

}