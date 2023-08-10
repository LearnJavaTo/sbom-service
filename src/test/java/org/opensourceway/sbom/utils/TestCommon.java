package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.model.cyclonedx.Component;
import org.opensourceway.sbom.model.cyclonedx.ComponentType;
import org.opensourceway.sbom.model.cyclonedx.CycloneDXDocument;
import org.opensourceway.sbom.model.cyclonedx.Dependency;
import org.opensourceway.sbom.model.cyclonedx.ExternalReference;
import org.opensourceway.sbom.model.cyclonedx.ExternalReferenceType;
import org.opensourceway.sbom.model.cyclonedx.Property;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.enums.SbomContentType;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.opensourceway.sbom.model.spdx.SpdxDocument;
import org.opensourceway.sbom.model.spdx.SpdxPackage;
import org.opensourceway.sbom.model.spdx.SpdxRelationship;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@Service
public class TestCommon {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private RawSbomRepository rawSbomRepository;

    public static void assertSpdxDocument(SpdxDocument spdxDocument) {
        assertThat(spdxDocument.getSpdxVersion()).isEqualTo("SPDX-2.2");
        assertThat(spdxDocument.getName()).isEqualTo("Unnamed document");
        assertThat(spdxDocument.getDataLicense()).isEqualTo("CC0-1.0");
        assertThat(spdxDocument.getCreationInfo().creators().size()).isEqualTo(1);
        assertThat(spdxDocument.getCreationInfo().creators().get(0)).isEqualTo("Tool: OSS Review Toolkit - e5b343ff71-dirty");
        assertThat(spdxDocument.getCreationInfo().licenseListVersion()).isEqualTo("3.16");
        assertThat(spdxDocument.getCreationInfo().created()).isEqualTo("2022-06-27T08:05:09Z");
        assertThat(spdxDocument.getDocumentNamespace()).isEqualTo("spdx://57eaa8d8-9572-44ff-ace4-d4ac38292265");
        assertThat(spdxDocument.getPackages().size()).isEqualTo(76);
        assertThat(spdxDocument.getRelationships().size()).isEqualTo(5);

        Optional<SpdxPackage> pkgOptional = spdxDocument.getPackages().stream()
                .filter(tempPkg -> StringUtils.endsWithIgnoreCase("SPDXRef-Package-github-abseil-cpp-20210324.2", tempPkg.getSpdxId()))
                .findFirst();
        assertThat(pkgOptional.isPresent()).isTrue();
        SpdxPackage pkg = pkgOptional.get();
        assertThat(pkg.getHomepage()).isEqualTo("https://abseil.io");
        assertThat(pkg.getLicenseDeclared()).isEqualTo("Apache-2.0");
        assertThat(pkg.getName()).isEqualTo("abseil-cpp");
        assertThat(pkg.getVersionInfo()).isEqualTo("20210324.2");

        SpdxRelationship relationship = spdxDocument.getRelationships().stream()
                .filter(it -> "SPDXRef-Package-PyPI-scipy-1.7.3".equals(it.spdxElementId()))
                .findFirst().orElse(null);
        assertThat(relationship).isNotNull();
        assertThat(relationship.spdxElementId()).isEqualTo("SPDXRef-Package-PyPI-scipy-1.7.3");
        assertThat(relationship.relationshipType().name()).isEqualTo(RelationshipType.DEPENDS_ON.name());
        assertThat(relationship.relatedSpdxElement()).isEqualTo("SPDXRef-Package-PyPI-numpy-1.21.6");
    }

    public static void assertCycloneDXDocument(CycloneDXDocument cycloneDXDocument) {
        assertThat(cycloneDXDocument.getBomFormat()).isEqualTo("CycloneDX");
        assertThat(cycloneDXDocument.getSpecVersion()).isEqualTo("1.4");
        assertThat(cycloneDXDocument.getMetadata().getTimestamp()).isEqualTo("2022-06-27T08:05:09Z");
        assertThat(cycloneDXDocument.getMetadata().getLicenses().get(0).getExpression()).isEqualTo("CC0-1.0");
        assertThat(cycloneDXDocument.getMetadata().getTools().get(0).getName()).isEqualTo("OSS Review Toolkit");
        assertThat(cycloneDXDocument.getMetadata().getTools().get(0).getVersion()).isEqualTo("e5b343ff71-dirty");
        assertThat(cycloneDXDocument.getMetadata().getComponent().getName()).isEqualTo("mindsporeTest");
        assertThat(cycloneDXDocument.getMetadata().getComponent().getType()).isEqualTo(ComponentType.APPLICATION);
        assertThat(cycloneDXDocument.getComponents().size()).isEqualTo(76);
        assertThat(cycloneDXDocument.getDependencies().size()).isEqualTo(76);

        Optional<Component> pkgOptional = cycloneDXDocument.getComponents().stream()
                .filter(tempPkg -> StringUtils.endsWithIgnoreCase("SPDXRef-Package-github-abseil-cpp-20210324.2", tempPkg.getBomRef()))
                .findFirst();
        assertThat(pkgOptional.isPresent()).isTrue();
        Component pkg = pkgOptional.get();
        Optional<ExternalReference> externalReferenceOptional = pkg.getExternalReferences().stream().filter(externalRef ->
                externalRef.getType().equals(ExternalReferenceType.WEBSITE)).findFirst();
        assertThat(externalReferenceOptional.isPresent()).isTrue();
        ExternalReference externalReference = externalReferenceOptional.get();
        assertThat(externalReference.getUrl()).isEqualTo("https://abseil.io");

        Optional<ExternalReference> externalReferenceOptional1 = pkg.getExternalReferences().stream().filter(externalRef ->
                externalRef.getType().equals(ExternalReferenceType.DISTRIBUTION)).findFirst();
        assertThat(externalReferenceOptional1.isPresent()).isTrue();
        ExternalReference externalReference1 = externalReferenceOptional1.get();
        assertThat(externalReference1.getUrl()).isEqualTo("NONE");

        assertThat(pkg.getLicenses().get(0).getExpression()).isEqualTo("NOASSERTION");
        assertThat(pkg.getName()).isEqualTo("abseil-cpp");
        assertThat(pkg.getVersion()).isEqualTo("20210324.2");
        assertThat(pkg.getType()).isEqualTo(ComponentType.LIBRARY);
        assertThat(pkg.getPurl()).isEqualTo("pkg:github/abseil-cpp@20210324.2");
        assertThat(pkg.getCopyright()).isEqualTo("NONE");

        Optional<Property> propertyOptional = pkg.getProperties().stream().filter(property ->
                property.getName().equals("summary")).findFirst();
        assertThat(propertyOptional.isPresent()).isTrue();
        Property property = propertyOptional.get();
        assertThat(property.getValue()).isEqualTo("Abseil Common Libraries (C++)");

        List<Dependency> dependencies = cycloneDXDocument.getDependencies();
        Optional<Dependency> dependencyOptional = dependencies.stream().filter(dependency ->
                dependency.getRef().equals("SPDXRef-Package-PyPI-asttokens-2.0.5")).findFirst();
        assertThat(dependencyOptional.isPresent()).isTrue();
        Dependency dependency = dependencyOptional.get();
        assertThat(dependency.getDependsOn().size()).isEqualTo(1);
        assertThat(dependency.getDependsOn().get(0)).isEqualTo("SPDXRef-Package-PyPI-six-1.16.0");

    }

    public void cleanPublishRawSbomData(String productName) {
        Optional<Product> productOptional = productRepository.findByName(productName);
        if (productOptional.isEmpty()) {
            return;
        }

        RawSbom condition = new RawSbom();
        condition.setProduct(productOptional.get());
        condition.setValueType(SbomContentType.SPDX_2_2_JSON_SBOM.getType());

        RawSbom existRawSbom = rawSbomRepository.queryRawSbom(condition);
        if (existRawSbom != null) {
            rawSbomRepository.delete(existRawSbom);
        }
    }

    public static String extractSbomFromTar(byte[] tarBytes, String filename) throws IOException {
        var tmpDirPath = Files.createTempDirectory("test");
        FileUtil.extractTarGzipArchive(new ByteArrayInputStream(tarBytes), tmpDirPath.toString());
        return Files.readString(tmpDirPath.resolve(filename));
    }
}
