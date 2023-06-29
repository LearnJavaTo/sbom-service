package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Describes a software package.
 */
@Entity
@Table(indexes = {
        @Index(name = "package_uk", columnList = "sbom_id, spdx_id, name, version", unique = true),
        @Index(name = "package_name_idx", columnList = "sbom_id, name")
})
public class Package {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Name of a package, e.g., "psutil", "numpy", "openssl".
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String name;

    /**
     * Version of a package.
     */
    @Column(columnDefinition = "TEXT")
    private String version;

    /**
     * Distribution source for a package.
     */
    @Column(columnDefinition = "TEXT")
    private String supplier;

    /**
     * Person or organization that originally created the package.
     */
    @Column(columnDefinition = "TEXT")
    private String originator;

    /**
     * A more detailed description of the package as opposed to [summary], which may be an extract from the package.
     */
    @Column(columnDefinition = "TEXT")
    private String description;

    /**
     * A text relating to a copyright notice, even if not complete.
     */
    @Column(columnDefinition = "TEXT")
    private String copyright;

    /**
     * A short description of the package.
     */
    @Column(columnDefinition = "TEXT")
    private String summary;

    /**
     * Homepage url of a package.
     */
    @Column(columnDefinition = "TEXT")
    private String homepage;

    /**
     * A unique identifier for a package within a sbom document.
     */
    @Column(columnDefinition = "TEXT", name = "spdx_id")
    private String spdxId;

    /**
     * Download location as url.
     */
    @Column(columnDefinition = "TEXT", name = "download_location")
    private String downloadLocation;

    /**
     * Indicates whether the file contents of the package have been used for the creation of the associated sbom document.
     */
    @Column(name = "files_analyzed")
    private Boolean filesAnalyzed;

    /**
     * Concluded license for the package as SPDX expression.
     * The licensing that the preparer of a sbom document has concluded, based on the evidence, actually applies to the package.
     */
    @Column(columnDefinition = "TEXT", name = "license_concluded")
    private String licenseConcluded;

    /**
     * Declared license for the package as SPDX expression.
     * The licensing that the creators of the software in the package, or the packager, have declared.
     */
    @Column(columnDefinition = "TEXT", name = "license_declared")
    private String licenseDeclared;

    /**
     * Any relevant background information or additional comments about the origin of the package.
     */
    @Column(columnDefinition = "TEXT", name = "source_info")
    private String sourceInfo;

    @OneToMany(mappedBy = "pkg", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private Set<PkgLicenseRelp> pkgLicenseRelps;

    /**
     * Checksums of a package.
     */
    @OneToMany(mappedBy = "pkg", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Checksum> checksums;

    /**
     * External vulnerability references of a package.
     */
    @OneToMany(mappedBy = "pkg", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<ExternalVulRef> externalVulRefs;

    /**
     * External purl references of a package.
     */
    @OneToMany(mappedBy = "pkg", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<ExternalPurlRef> externalPurlRefs;

    /**
     * Sbom that a package belongs to.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sbom_id", foreignKey = @ForeignKey(name = "sbom_id_fk"))
    @JsonIgnore
    private Sbom sbom;

    /**
     * Verification code of a package.
     */
    @OneToOne(mappedBy = "pkg", cascade = CascadeType.ALL, orphanRemoval = true)
    private PkgVerfCode pkgVerfCode;

    /**
     * Statistics of a package.
     */
    @OneToOne(mappedBy = "pkg", cascade = CascadeType.ALL, orphanRemoval = true)
    private PackageStatistics packageStatistics;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSupplier() {
        return supplier;
    }

    public void setSupplier(String supplier) {
        this.supplier = supplier;
    }

    public String getOriginator() {
        return originator;
    }

    public void setOriginator(String originator) {
        this.originator = originator;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCopyright() {
        return copyright;
    }

    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getHomepage() {
        return homepage;
    }

    public void setHomepage(String homepage) {
        this.homepage = homepage;
    }

    public String getSpdxId() {
        return spdxId;
    }

    public void setSpdxId(String spdxId) {
        this.spdxId = spdxId;
    }

    public String getDownloadLocation() {
        return downloadLocation;
    }

    public void setDownloadLocation(String downloadLocation) {
        this.downloadLocation = downloadLocation;
    }

    public Boolean isFilesAnalyzed() {
        return filesAnalyzed;
    }

    public void setFilesAnalyzed(Boolean filesAnalyzed) {
        this.filesAnalyzed = filesAnalyzed;
    }

    public String getLicenseConcluded() {
        return licenseConcluded;
    }

    public void setLicenseConcluded(String licenseConcluded) {
        this.licenseConcluded = licenseConcluded;
    }

    public String getLicenseDeclared() {
        return licenseDeclared;
    }

    public void setLicenseDeclared(String licenseDeclared) {
        this.licenseDeclared = licenseDeclared;
    }

    public String getSourceInfo() {
        return sourceInfo;
    }

    public void setSourceInfo(String sourceInfo) {
        this.sourceInfo = sourceInfo;
    }

    public Set<PkgLicenseRelp> getPkgLicenseRelps() {
        return pkgLicenseRelps;
    }

    public void setPkgLicenseRelps(Set<PkgLicenseRelp> pkgLicenseRelps) {
        this.pkgLicenseRelps = pkgLicenseRelps;
    }

    public void addPkgLicenseRelp(PkgLicenseRelp pkgLicenseRelp) {
        if (Objects.isNull(pkgLicenseRelps)) {
            pkgLicenseRelps = new HashSet<>();
        }
        pkgLicenseRelps.add(pkgLicenseRelp);
    }

    public List<Checksum> getChecksums() {
        return checksums;
    }

    public void setChecksums(List<Checksum> checksums) {
        if (Objects.isNull(this.checksums)) {
            this.checksums = checksums;
        } else {
            this.checksums.clear();
            this.checksums.addAll(checksums);
        }
    }

    public List<ExternalVulRef> getExternalVulRefs() {
        return externalVulRefs;
    }

    public void setExternalVulRefs(List<ExternalVulRef> externalVulRefs) {
        if (Objects.isNull(this.externalVulRefs)) {
            this.externalVulRefs = externalVulRefs;
        } else {
            this.externalVulRefs.clear();
            this.externalVulRefs.addAll(externalVulRefs);
        }
    }

    public List<ExternalPurlRef> getExternalPurlRefs() {
        return externalPurlRefs;
    }

    public void setExternalPurlRefs(List<ExternalPurlRef> externalPurlRefs) {
        if (Objects.isNull(this.externalPurlRefs)) {
            this.externalPurlRefs = externalPurlRefs;
        } else {
            this.externalPurlRefs.clear();
            this.externalPurlRefs.addAll(externalPurlRefs);
        }
    }

    public Sbom getSbom() {
        return sbom;
    }

    public void setSbom(Sbom sbom) {
        this.sbom = sbom;
    }

    public PkgVerfCode getPkgVerfCode() {
        return pkgVerfCode;
    }

    public void setPkgVerfCode(PkgVerfCode pkgVerfCode) {
        this.pkgVerfCode = pkgVerfCode;
    }

    public PackageStatistics getPackageStatistics() {
        return packageStatistics;
    }

    public void setPackageStatistics(PackageStatistics packageStatistics) {
        this.packageStatistics = packageStatistics;
    }

    public Boolean containLicense(License license) {
        return pkgLicenseRelps.stream()
                .map(PkgLicenseRelp::getLicense)
                .anyMatch(lic -> lic.getSpdxLicenseId().equals(license.getSpdxLicenseId()));
    }
}
