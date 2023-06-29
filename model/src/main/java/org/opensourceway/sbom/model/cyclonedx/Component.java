package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Component {

    private ComponentType type;

    private String name;

    @JsonProperty("bom-ref")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String bomRef;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Supplier supplier;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String author;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String group;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String version;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String description;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Hash> hashes;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<License> licenses;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String copyright;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String purl;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ExternalReference> externalReferences;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Component> components;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Pedigree pedigree;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Property> properties;

    public Component(String name) {
        this.name = name;
    }

    public Component() {
    }

    public String getBomRef() {
        return bomRef;
    }

    public void setBomRef(String bomRef) {
        this.bomRef = bomRef;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<License> getLicenses() {
        return licenses;
    }

    public void setLicenses(List<License> licenses) {
        this.licenses = licenses;
    }

    public String getCopyright() {
        return copyright;
    }

    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public ComponentType getType() {
        return type;
    }

    public void setType(ComponentType type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Supplier getSupplier() {
        return supplier;
    }

    public void setSupplier(Supplier supplier) {
        this.supplier = supplier;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<Hash> getHashes() {
        return hashes;
    }

    public void setHashes(List<Hash> hashes) {
        this.hashes = hashes;
    }

    public List<ExternalReference> getExternalReferences() {
        return externalReferences;
    }

    public void setExternalReferences(List<ExternalReference> externalReferences) {
        this.externalReferences = externalReferences;
    }

    public Pedigree getPedigree() {
        return pedigree;
    }

    public void setPedigree(Pedigree pedigree) {
        this.pedigree = pedigree;
    }

    public List<Property> getProperties() {
        return properties;
    }

    public void setProperties(List<Property> properties) {
        this.properties = properties;
    }

    public List<Component> getComponents() {
        return components;
    }

    public void setComponents(List<Component> components) {
        this.components = components;
    }
}
