package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.util.UUID;

/**
 * External vulnerability reference of a package.
 */
@Entity
@TypeDefs({
        @TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
})
@Table(indexes = {
        @Index(name = "package_vul_purl_uk", columnList = "pkg_id, vul_id, purl", unique = true)
})
public class ExternalVulRef {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Category for the external reference.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String category;

    /**
     * Human-readable information about the purpose and target of the reference.
     */
    @Column(columnDefinition = "TEXT")
    private String comment;

    /**
     * Purl of the software component that the vulnerability belongs to.
     */
    @Column(columnDefinition = "JSONB")
    @Type(type = "jsonb")
    private PackageUrlVo purl;

    /**
     * Vulnerability of the reference.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vul_id", foreignKey = @ForeignKey(name = "vul_id_fk"))
    @JsonIgnore
    private Vulnerability vulnerability;

    /**
     * Package of the reference.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "pkg_id", foreignKey = @ForeignKey(name = "pkg_id_fk"))
    @JsonIgnore
    private Package pkg;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public PackageUrlVo getPurl() {
        return purl;
    }

    public void setPurl(PackageUrlVo purl) {
        this.purl = purl;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public Package getPkg() {
        return pkg;
    }

    public void setPkg(Package pkg) {
        this.pkg = pkg;
    }
}
