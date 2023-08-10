package org.opensourceway.sbom.model.pojo.response.vul.uvp;

import java.io.Serializable;
import java.util.Objects;

public class Reference implements Serializable {
    private String type;

    private String url;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Reference reference = (Reference) o;
        return Objects.equals(type, reference.type) && Objects.equals(url, reference.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, url);
    }
}
