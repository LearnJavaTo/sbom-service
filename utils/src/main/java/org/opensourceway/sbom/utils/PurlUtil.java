package org.opensourceway.sbom.utils;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.springframework.data.util.Pair;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.TreeMap;

public class PurlUtil {
    public static PackageURL newPackageURL(String purlStr) {
        try {
            return new PackageURL(encodePurl(purlStr));
        } catch (MalformedPackageURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static String encodePurl(String purl) {
        return URLEncoder.encode(purl, StandardCharsets.UTF_8)
                .replace("%3A", ":")
                .replace("%2F", "/")
                .replace("%40", "@")
                .replace("%3F", "?")
                .replace("%3D", "=")
                .replace("%26", "&")
                .replace("%23", "#");
    }

    public static PackageURL newPackageURL(final String type, final String namespace, final String name,
            final String version, final TreeMap<String, String> qualifiers,
            final String subpath) {
        try {
            return new PackageURL(type, namespace, name, version, qualifiers, subpath);
        } catch (MalformedPackageURLException e) {
            throw new RuntimeException(e);
        }
    }

    public static PackageURL newPackageURL(final String type, final String name) throws MalformedPackageURLException {
        return newPackageURL(type, null, name, null, null, null);
    }

    public static String canonicalizePurl(PackageURL purl) {
        return purl.canonicalize()
                .replace("%20", "+")
                .replace("%2B", "+")
                .replace("%2A", "*");
    }

    public static String canonicalizePurl(String purl) {
        return canonicalizePurl(newPackageURL(purl));
    }

    public static String canonicalizePurl(PackageUrlVo vo) {
        return canonicalizePurl(packageUrlVoToPackageURL(vo));
    }

    public static PackageUrlVo strToPackageUrlVo(String purlStr) {
        PackageURL packageURL = newPackageURL(purlStr);
        return new PackageUrlVo(packageURL.getScheme(), packageURL.getType(), packageURL.getNamespace(),
                packageURL.getName(), packageURL.getVersion(), (TreeMap<String, String>) packageURL.getQualifiers(),
                packageURL.getSubpath());
    }

    public static PackageURL packageUrlVoToPackageURL(PackageUrlVo vo) {
        return PurlUtil.newPackageURL(vo.getType(), vo.getNamespace(), vo.getName(), vo.getVersion(),
                vo.getQualifiers(), vo.getSubpath());
    }

    public static String convertPackageType(PackageUrlVo vo, String type) {
        PackageURL packageURL = packageUrlVoToPackageURL(vo);
        return canonicalizePurl(PurlUtil.newPackageURL(type, packageURL.getNamespace(), packageURL.getName(), packageURL.getVersion(),
                (TreeMap<String, String>) packageURL.getQualifiers(), packageURL.getSubpath()));
    }

    @Deprecated
    public static Pair<String, Boolean> generatePurlQueryCondition(PackageUrlVo purl) throws MalformedPackageURLException {
        String type = StringUtils.lowerCase(purl.getType());
        switch (type) {
            case "maven":
                return PurlUtil.generateMavenPurlQueryCondition(purl.getNamespace(), purl.getName(), purl.getVersion());
            case "rpm":
                return PurlUtil.generateRpmPurlQueryCondition(type, purl.getName(), purl.getVersion());
            case "pypi":
            case "github":
            case "gitlab":
            case "gitee":
                return PurlUtil.generateNoNamespacePurlQueryCondition(type, purl.getName(), purl.getVersion());
            // TODO 后续追加其他包管理的支持
        }

        throw new RuntimeException("purl query condition not support type: " + type);
    }

    @Deprecated
    private static Pair<String, Boolean> generateMavenPurlQueryCondition(String namespace, String name, String version) throws MalformedPackageURLException {
        String type = "maven";
        if (StringUtils.isNotEmpty(namespace) && StringUtils.isNotEmpty(name) && StringUtils.isNotEmpty(version)) {
            PackageURL purl = new PackageURL(type, namespace, name, version, null, null);
            return Pair.of(purl.getCoordinates(), true);
        } else if (StringUtils.isNotEmpty(namespace) && StringUtils.isNotEmpty(name)) {
            PackageURL purl = new PackageURL(type, namespace, name, null, null, null);
            return Pair.of(purl.getCoordinates(), false);
        } else if (StringUtils.isNotEmpty(name)) {
            return Pair.of(SbomConstants.PURL_SCHEMA_DEFAULT + ":" + type + "%" + name, false);
        } else {
            throw new RuntimeException("maven purl query condition params is error, namespace: %s, name: %s, version: %s".formatted(namespace, name, version));
        }
    }

    /**
     * RPM PURL使用name+version
     * <p>
     * 但是RPM的version比较特殊，使用epoch:version-release格式，转成PURL之后，PURL中的version为version-release；epoch放在PURL的qualifiers中，<a href="https://github.com/package-url/purl-spec/issues/69">https://github.com/package-url/purl-spec/issues/69</a>
     */
    @Deprecated
    private static Pair<String, Boolean> generateRpmPurlQueryCondition(String type, String name, String version) throws MalformedPackageURLException {
        if (StringUtils.isNotEmpty(name) && StringUtils.isNotEmpty(version)) {
            PackageURL purl = new PackageURL(type, null, name, version, null, null);
            return Pair.of(purl.getCoordinates(), false);
        } else if (StringUtils.isNotEmpty(name)) {
            return Pair.of(SbomConstants.PURL_SCHEMA_DEFAULT + ":" + type + "%" + name, false);
        } else {
            throw new RuntimeException("maven purl query condition params is error, type: %s, name: %s, version: %s".formatted(type, name, version));
        }
    }

    @Deprecated
    private static Pair<String, Boolean> generateNoNamespacePurlQueryCondition(String type, String name, String version) throws MalformedPackageURLException {
        if (StringUtils.isNotEmpty(name) && StringUtils.isNotEmpty(version)) {
            PackageURL purl = new PackageURL(type, null, name, version, null, null);
            return Pair.of(purl.getCoordinates(), true);
        } else if (StringUtils.isNotEmpty(name)) {
            return Pair.of(SbomConstants.PURL_SCHEMA_DEFAULT + ":" + type + "%" + name, false);
        } else {
            throw new RuntimeException("maven purl query condition params is error, type: %s, name: %s, version: %s".formatted(type, name, version));
        }
    }

    public static PackageURL convertPurlForVulnMatch(PackageURL purl) {
        String version = StringUtils.equals(purl.getType(), PackageURL.StandardTypes.RPM) ?
                purl.getVersion().split("-")[0] : purl.getVersion();
        return newPackageURL(PackageURL.StandardTypes.GENERIC, null, purl.getName(), version, null, null);
    }

}
