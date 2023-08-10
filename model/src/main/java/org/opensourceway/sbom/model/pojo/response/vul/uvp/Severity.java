package org.opensourceway.sbom.model.pojo.response.vul.uvp;

import java.util.Objects;

public class Severity {
    private String type;

    private String score;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getScore() {
        return score;
    }

    public void setScore(String score) {
        this.score = score;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Severity severity = (Severity) o;
        return Objects.equals(type, severity.type) && Objects.equals(score, severity.score);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, score);
    }
}
