package org.opensourceway.sbom.service.writer.impl.spdx;

import org.opensourceway.sbom.api.writer.SbomWriter;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Checksum;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgVerfCode;
import org.opensourceway.sbom.model.entity.PkgVerfCodeExcludedFile;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomCreator;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.spdx.Algorithm;
import org.opensourceway.sbom.model.spdx.FileType;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.opensourceway.sbom.model.spdx.SpdxChecksum;
import org.opensourceway.sbom.model.spdx.SpdxCreationInfo;
import org.opensourceway.sbom.model.spdx.SpdxDocument;
import org.opensourceway.sbom.model.spdx.SpdxExternalReference;
import org.opensourceway.sbom.model.spdx.SpdxFile;
import org.opensourceway.sbom.model.spdx.SpdxPackage;
import org.opensourceway.sbom.model.spdx.SpdxPackageVerificationCode;
import org.opensourceway.sbom.model.spdx.SpdxRelationship;
import org.opensourceway.sbom.utils.PurlUtil;
import org.opensourceway.sbom.utils.SbomMapperUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service(value = SbomConstants.SPDX_NAME + SbomConstants.WRITER_NAME)
@Transactional(rollbackFor = Exception.class)
public class SpdxWriter implements SbomWriter {
    private static final String SPDX_VERSION = "SPDX-2.2";
    @Autowired
    private SbomRepository sbomRepository;

    @Override
    public byte[] write(String productName, SbomFormat format) throws IOException {
        Sbom sbom = sbomRepository.findByProductName(productName).orElseThrow(() -> new RuntimeException("can't find %s's sbom metadata".formatted(productName)));
        SpdxDocument document = new SpdxDocument(sbom.getId().toString());

        document.setSpdxVersion(SPDX_VERSION);
        setCreationInfo(sbom, document);
        document.setName(sbom.getName());
        document.setDataLicense(sbom.getDataLicense());
        document.setComment(null);
        document.setExternalDocumentRefs(null);
        document.setHasExtractedLicensingInfos(null);
        document.setAnnotations(null);
        document.setDocumentNamespace(sbom.getNamespace());
        document.setDocumentDescribes(null);
        document.setPackages(sbom.getPackages().stream().map(this::transformPackage).toList());
        document.setFiles(sbom.getFiles().stream().filter(Objects::nonNull).map(this::transformFile).toList());
        document.setSnippets(null);
        document.setRelationships(sbom.getSbomElementRelationships().stream().filter(Objects::nonNull).map(this::transformRelationship).toList());

        return SbomMapperUtil.writeAsBytes(document, format);
    }

    private void setCreationInfo(Sbom sbom, SpdxDocument document) {
        List<String> creators = sbom.getSbomCreators().stream().map(SbomCreator::getName).collect(Collectors.toList());
        SpdxCreationInfo creationInfo = new SpdxCreationInfo(null, sbom.getCreated(), creators, sbom.getLicenseListVersion());
        document.setCreationInfo(creationInfo);
    }

    private SpdxPackage transformPackage(Package pkg) {
        SpdxPackage spdxPackage = new SpdxPackage(pkg.getSpdxId());

        spdxPackage.setAnnotations(null);
        spdxPackage.setAttributionTexts(null);
        spdxPackage.setChecksums(pkg.getChecksums().stream().filter(Objects::nonNull).map(this::transformChecksum).toList());
        spdxPackage.setComment(null);
        spdxPackage.setCopyrightText(pkg.getCopyright());
        spdxPackage.setDescription(pkg.getDescription());
        spdxPackage.setDownloadLocation(pkg.getDownloadLocation());
        setExternalRefs(pkg, spdxPackage);
        spdxPackage.setFilesAnalyzed(pkg.isFilesAnalyzed());
        spdxPackage.setHasFiles(null);
        spdxPackage.setHomepage(pkg.getHomepage());
        spdxPackage.setLicenseComments(null);
        spdxPackage.setLicenseConcluded(pkg.getLicenseConcluded());
        spdxPackage.setLicenseDeclared(pkg.getLicenseDeclared());
        spdxPackage.setLicenseInfoFromFiles(null);
        spdxPackage.setName(pkg.getName());
        spdxPackage.setOriginator(null);
        spdxPackage.setPackageFilename(null);
        spdxPackage.setPackageVerificationCode(transformPkgVerfCode(pkg.getPkgVerfCode()));
        spdxPackage.setSourceInfo(pkg.getSourceInfo());
        spdxPackage.setSummary(pkg.getSummary());
        spdxPackage.setSupplier(pkg.getSupplier());
        spdxPackage.setOriginator(pkg.getOriginator());
        spdxPackage.setVersionInfo(pkg.getVersion());

        return spdxPackage;
    }

    private SpdxChecksum transformChecksum(Checksum checksum) {
        return new SpdxChecksum(Algorithm.valueOf(checksum.getAlgorithm()), checksum.getValue());
    }

    private void setExternalRefs(Package pkg, SpdxPackage spdxPackage) {
        List<SpdxExternalReference> spdxExternalReferences = new ArrayList<>(
                pkg.getExternalPurlRefs().stream().map(this::transformExternalPurlRef).collect(Collectors.toSet()).stream().toList());
        spdxExternalReferences.addAll(pkg.getExternalVulRefs().stream()
                .map(this::transformExternalVulRef).collect(Collectors.toSet()).stream().toList());
        spdxPackage.setExternalRefs(spdxExternalReferences);
    }

    private SpdxExternalReference transformExternalPurlRef(ExternalPurlRef ref) {
        if (Objects.isNull(ref)) {
            return null;
        }
        if (ReferenceType.URL == ReferenceType.findReferenceType(ref.getType())) {
            return new SpdxExternalReference(ref.getComment(), ReferenceCategory.valueOf(ref.getCategory()),
                    ReferenceType.findReferenceType(ref.getType()), ref.getPurl().getName());
        } else {
            return new SpdxExternalReference(ref.getComment(), ReferenceCategory.valueOf(ref.getCategory()),
                    ReferenceType.findReferenceType(ref.getType()), PurlUtil.canonicalizePurl(ref.getPurl()));
        }
    }

    private SpdxExternalReference transformExternalVulRef(ExternalVulRef ref) {
        if (Objects.isNull(ref)) {
            return null;
        }

        return new SpdxExternalReference(ref.getComment(), ReferenceCategory.valueOf(ref.getCategory()),
                ReferenceType.findReferenceType(ref.getType()), ref.getVulnerability().getVulId());
    }

    private SpdxPackageVerificationCode transformPkgVerfCode(PkgVerfCode pkgVerfCode) {
        if (Objects.isNull(pkgVerfCode)) {
            return null;
        }

        return new SpdxPackageVerificationCode(
                pkgVerfCode.getPkgVerfCodeExcludedFiles().stream().map(PkgVerfCodeExcludedFile::getFile).toList(),
                pkgVerfCode.getValue());
    }

    private SpdxRelationship transformRelationship(SbomElementRelationship relationship) {
        return new SpdxRelationship(relationship.getElementId(), RelationshipType.valueOf(relationship.getRelationshipType()),
                relationship.getRelatedElementId(), relationship.getComment());
    }

    private SpdxFile transformFile(File file) {
        return new SpdxFile(file.getSpdxId(),
                null, null, null,
                file.getCopyrightText(),
                null, null,
                file.getFileName(),
                file.getFileTypes() == null ? null : Arrays.stream(file.getFileTypes()).map(FileType::findFileType).collect(Collectors.toList()),
                file.getLicenseComments(),
                file.getLicenseConcluded(),
                file.getLicenseInfoInFiles() == null ? null : Arrays.asList(file.getLicenseInfoInFiles()),
                null);
    }

    @Override
    public byte[] writePackage(String productName, String pkgName, String pkgVersion, SbomFormat format) throws IOException {
        throw new RuntimeException("Not implemented");
    }
}
