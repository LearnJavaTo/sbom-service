package org.opensourceway.sbom.service.sbom.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.TraceDataAnalyzer;
import org.opensourceway.sbom.api.reader.SbomReader;
import org.opensourceway.sbom.api.sbom.SbomService;
import org.opensourceway.sbom.api.writer.SbomWriter;
import org.opensourceway.sbom.cache.ProductConfigCache;
import org.opensourceway.sbom.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.dao.LicenseRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.ProductConfigRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.ProductStatisticsRepository;
import org.opensourceway.sbom.dao.ProductTypeRepository;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.dao.VulnerabilityRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.echarts.Edge;
import org.opensourceway.sbom.model.echarts.Graph;
import org.opensourceway.sbom.model.echarts.Node;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgLicenseRelp;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductConfig;
import org.opensourceway.sbom.model.entity.ProductConfigValue;
import org.opensourceway.sbom.model.entity.ProductStatistics;
import org.opensourceway.sbom.model.entity.ProductType;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.entity.Vulnerability;
import org.opensourceway.sbom.model.enums.SbomContentType;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.enums.SbomSpecification;
import org.opensourceway.sbom.model.pojo.request.sbom.AddProductRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.QuerySbomPackagesRequest;
import org.opensourceway.sbom.model.pojo.response.sbom.PublishResultResponse;
import org.opensourceway.sbom.model.pojo.vo.sbom.BinaryManagementItemVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.BinaryManagementVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.CopyrightVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.LicenseVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackagePurlVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageWithStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PageVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.ProductConfigVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulCountVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulnerabilityVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.opensourceway.sbom.model.spec.ExternalPurlRefSpecs;
import org.opensourceway.sbom.utils.EntityUtil;
import org.opensourceway.sbom.utils.FileUtil;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.utils.PublishSbomRequestValidator;
import org.opensourceway.sbom.utils.PurlUtil;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
import org.opensourceway.sbom.utils.SbomMapperUtil;
import org.opensourceway.sbom.utils.UrlUtil;
import org.opensourceway.sbom.utils.VersionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@Transactional(rollbackFor = Exception.class)
public class SbomServiceImpl implements SbomService {

    private static final Logger logger = LoggerFactory.getLogger(SbomServiceImpl.class);

    @Autowired
    private RawSbomRepository sbomFileRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Autowired
    private ProductTypeRepository productTypeRepository;

    @Autowired
    private ProductConfigRepository productConfigRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private TraceDataAnalyzer traceDataAnalyzer;

    @Autowired
    private ProductStatisticsRepository productStatisticsRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ProductConfigCache productConfigCache;

    @Value("${sbom.service.website.domain}")
    private String sbomWebsiteDomain;

    @Value("${product_type.addable}")
    private String[] addableProductTypes;

    @Override
    public UUID publishSbom(PublishSbomRequest publishSbomRequest) {
        PublishSbomRequestValidator.validate(publishSbomRequest);

        Product product = productRepository.findByName(publishSbomRequest.getProductName())
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(publishSbomRequest.getProductName())));

        RawSbom rawSbom = new RawSbom();
        rawSbom.setProduct(product);
        rawSbom.setValue(publishSbomRequest.getSbomContent().getBytes(StandardCharsets.UTF_8));
        rawSbom.setValueType(publishSbomRequest.getSbomContentType());

        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_WAIT);
        rawSbom.setTaskId(UUID.randomUUID());

        RawSbom oldRawSbom = sbomFileRepository.queryRawSbom(rawSbom);
        if (oldRawSbom != null) {
            // oldRawSbom.getTaskStatus() maybe null for finish job
            if (Objects.nonNull(oldRawSbom.getTaskStatus()) &&
                    !List.of(SbomConstants.TASK_STATUS_FINISH, SbomConstants.TASK_STATUS_FAILED_FINISH)
                            .contains(oldRawSbom.getTaskStatus())) {
                throw new RuntimeException("product: %s has sbom import job in running.".formatted(publishSbomRequest.getProductName()));
            }
            rawSbom.setId(oldRawSbom.getId());
            rawSbom.setCreateTime(oldRawSbom.getCreateTime());
        }
        sbomFileRepository.save(rawSbom);

        return rawSbom.getTaskId();
    }

    /**
     * taskStatus and response status mappings
     * <p>
     * Success[true], finish[false]: WAIT，RUNNING，FAILED, others
     * <p>
     * Success[true], finish[true]: FINISH_PARSE，FINISH
     * <p>
     * Success[false], finish[false]: FAILED_FINISH
     */
    @Override
    public PublishResultResponse getSbomPublishResult(UUID taskId) {
        Optional<RawSbom> rawSbomOptional = sbomFileRepository.findByTaskId(taskId);

        return rawSbomOptional.map(rawSbom -> {
            PublishResultResponse response = new PublishResultResponse();
            if (List.of(SbomConstants.TASK_STATUS_FINISH_PARSE,
                            SbomConstants.TASK_STATUS_FINISH)
                    .contains(rawSbom.getTaskStatus())) {
                response.setSuccess(Boolean.TRUE);
                response.setFinish(Boolean.TRUE);
                response.setSbomRef(UrlUtil.generateSbomUrl(sbomWebsiteDomain, rawSbom.getProduct().getName()));
            } else if (Objects.equals(SbomConstants.TASK_STATUS_FAILED_FINISH, rawSbom.getTaskStatus())) {
                response.setSuccess(Boolean.FALSE);
                response.setFinish(Boolean.FALSE);
            } else {
                response.setSuccess(Boolean.TRUE);
                response.setFinish(Boolean.FALSE);
            }
            return response;
        }).orElse(
                new PublishResultResponse(Boolean.FALSE,
                        Boolean.FALSE,
                        SbomConstants.TASK_STATUS_NOT_EXISTS,
                        null)
        );
    }

    @Override
    public void readSbomFile(String productName, String fileName, byte[] fileContent) throws IOException {
        SbomFormat format = SbomMapperUtil.fileToExt(fileName);
        SbomSpecification specification = SbomMapperUtil.fileToSpec(format, fileContent);

        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));

        RawSbom rawSbom = new RawSbom();
        rawSbom.setProduct(product);
        rawSbom.setValue(fileContent);
        rawSbom.setValueType(SbomContentType.findBySpecAndFormat(specification, format).getType());

        RawSbom oldRawSbom = sbomFileRepository.queryRawSbom(rawSbom);
        if (oldRawSbom != null) {
            rawSbom.setId(oldRawSbom.getId());
            rawSbom.setCreateTime(oldRawSbom.getCreateTime());
        }
        sbomFileRepository.save(rawSbom);

        SbomReader sbomReader = SbomApplicationContextHolder.getSbomReader(specification.getSpecification());
        sbomReader.read(productName, format, fileContent);
    }

    @Override
    public RawSbom writeSbomFile(String productName, String spec, String specVersion, String format) {
        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));

        format = StringUtils.lowerCase(format);
        spec = StringUtils.lowerCase(spec);

        if (!SbomFormat.EXT_TO_FORMAT.containsKey(format)) {
            throw new RuntimeException("sbom file format: %s is not support".formatted(format));
        }
        if (SbomSpecification.findSpecification(spec, specVersion) == null) {
            throw new RuntimeException("sbom file specification: %s - %s is not support".formatted(spec, specVersion));
        }

        RawSbom queryCondition = new RawSbom();
        queryCondition.setProduct(product);
        queryCondition.setValueType(SbomContentType.findBySpecAndFormat(
                SbomSpecification.findSpecification(spec, specVersion), SbomFormat.findSbomFormat(format)).getType());

        return sbomFileRepository.queryRawSbom(queryCondition);
    }

    @Override
    public byte[] writeSbom(String productName, String spec, String specVersion, String format) throws IOException {
        format = StringUtils.lowerCase(format);
        spec = StringUtils.lowerCase(spec);

        if (!SbomFormat.EXT_TO_FORMAT.containsKey(format)) {
            throw new RuntimeException("sbom file format: %s is not support".formatted(format));
        }

        SbomSpecification sbomSpec = SbomSpecification.findSpecification(spec, specVersion);
        if (sbomSpec == null) {
            throw new RuntimeException("sbom file specification: %s - %s is not support".formatted(spec, specVersion));
        }

        SbomWriter sbomWriter = SbomApplicationContextHolder.getSbomWriter(sbomSpec.getSpecification());
        return sbomWriter.write(productName, SbomFormat.EXT_TO_FORMAT.get(format));
    }

    @Override
    public PageVo<Package> findPackagesPageable(String productName, int page, int size) {
        Sbom sbom = sbomRepository.findByProductName(productName).orElseThrow(() -> new RuntimeException("can't find %s `s sbom metadata".formatted(productName)));

        Pageable pageable = PageRequest.of(page, size).withSort(Sort.by(Sort.Order.by("name")));
        return new PageVo<>((PageImpl<Package>) packageRepository.findPackagesBySbomIdForPage(sbom.getId(), pageable));
    }

    @Override
    public List<PackageWithStatisticsVo> queryPackageInfoByName(String productName, String packageName, boolean isExactly) {
        String equalPackageName = isExactly ? packageName : null;

        return packageRepository.getPackageInfoByName(productName, equalPackageName, packageName, SbomConstants.MAX_QUERY_LINE)
                .stream()
                .map(this::packageWithStatisticsVoFromPackage)
                .toList();
    }

    @Override
    public Package queryPackageInfoById(String packageId) {
        return packageRepository.findById(UUID.fromString(packageId)).orElse(null);
    }

    @Override
    public PageVo<PackageWithStatisticsVo> getPackageInfoByNameForPage(QuerySbomPackagesRequest req) {
        Pageable pageable = PageRequest.of(req.getPage(), req.getSize()).withSort(Sort.by(Sort.Order.by("name")));
        Page<Package> result = packageRepository.getPackageInfoByNameForPage(req.getProductName(), req.getExactly(),
                req.getPackageName(), req.getVulSeverity(), req.getNoLicense(), req.getMultiLicense(),
                req.getLegalLicense(), req.getLicenseId(), pageable);
        return new PageVo<>(new PageImpl<>(result.stream().map(this::packageWithStatisticsVoFromPackage).toList(),
                result.getPageable(), result.getTotalElements()));
    }

    @Override
    public BinaryManagementVo queryPackageBinaryManagement(String packageId, String binaryType) {
        UUID packageUUID = UUID.fromString(packageId);
        ReferenceCategory referenceCategory = ReferenceCategory.findReferenceCategory(binaryType);
        if (referenceCategory != null && !ReferenceCategory.BINARY_TYPE.contains(referenceCategory)) {
            throw new RuntimeException("binary type: %s is not support".formatted(binaryType));
        }

        BinaryManagementVo vo = new BinaryManagementVo();
        if (referenceCategory == null || referenceCategory == ReferenceCategory.PACKAGE_MANAGER) {
            vo.setPackageList(externalPurlRefRepository.queryPackageRef(
                            packageUUID, ReferenceCategory.PACKAGE_MANAGER.name(), ReferenceType.PURL.getType())
                    .stream().map(BinaryManagementItemVo::fromExternalPurlRef).toList());
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.PROVIDE_MANAGER) {
            vo.setProvideList(externalPurlRefRepository.queryPackageRef(
                            packageUUID, ReferenceCategory.PROVIDE_MANAGER.name(), ReferenceType.PURL.getType())
                    .stream().map(BinaryManagementItemVo::fromExternalPurlRef).toList());
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.EXTERNAL_MANAGER) {
            vo.setExternalList(externalPurlRefRepository.queryPackageRef(
                            packageUUID, ReferenceCategory.EXTERNAL_MANAGER.name(), ReferenceType.PURL.getType())
                    .stream().map(BinaryManagementItemVo::fromExternalPurlRef).toList());
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.RELATIONSHIP_MANAGER) {
            packageRepository.findById(packageUUID)
                    .ifPresentOrElse(pkg -> vo.setRelationshipList(externalPurlRefRepository.queryRelationPackageRef(
                                            pkg.getSbom().getId(), pkg.getSpdxId())
                                    .stream().map(BinaryManagementItemVo::fromExternalPurlRef).toList()),
                            () -> vo.setRelationshipList(Lists.newArrayList()));
        }
        return vo;
    }

    @Override
    public PageVo<PackagePurlVo> queryPackageInfoByBinaryViaSpec(ExternalPurlRefCondition condition, Pageable pageable) {
        ReferenceCategory referenceCategory = ReferenceCategory.findReferenceCategory(condition.getBinaryType());
        if (!ReferenceCategory.BINARY_TYPE.contains(referenceCategory)) {
            throw new RuntimeException("binary type: %s is not support".formatted(condition.getBinaryType()));
        }
        Sbom sbom = sbomRepository.findByProductName(condition.getProductName())
                .orElseThrow(() -> new RuntimeException("can't find %s's sbom metadata".formatted(condition.getProductName())));
        condition.setSbomId(sbom.getId());
        condition.setSortField("name");

        /*
          指定版本非空或者版本上下限均为空时，按分页查询处理
          指定版本为空并且版本上下限任一非空时，先查出所有符合条件的组件再根据版本范围过滤，最后返回一个假分页
          */
        if (!StringUtils.equalsIgnoreCase(condition.getBinaryType(), ReferenceCategory.RELATIONSHIP_MANAGER.name())
                && StringUtils.isEmpty(condition.getVersion())
                && (StringUtils.isNotEmpty(condition.getStartVersion()) || StringUtils.isNotEmpty(condition.getEndVersion()))) {
            List<ExternalPurlRef> result = queryPackageInfoByBinaryFromDB(condition, null).getContent();
            List<ExternalPurlRef> filteredResult = filterVersionRange(condition, result);
            List<ExternalPurlRef> pagedResult = pageList(filteredResult, pageable);

            return new PageVo<>(new PageImpl(pagedResult.stream().map(this::fromExternalPurlRef).toList(),
                    PageRequest.of(pageable.getPageNumber(), pageable.getPageSize()), filteredResult.size()));
        }

        Page<ExternalPurlRef> result = queryPackageInfoByBinaryFromDB(condition, pageable);
        return new PageVo<>(new PageImpl(result.stream().map(this::fromExternalPurlRef).collect(Collectors.toList()),
                result.getPageable(),
                result.getTotalElements()));
    }

    private PackagePurlVo fromExternalPurlRef(ExternalPurlRef externalPurlRef) {
        PackagePurlVo packagePurlVo = new PackagePurlVo();

        packagePurlVo.setId(externalPurlRef.getPkg().getId().toString());
        packagePurlVo.setName(externalPurlRef.getPkg().getName());
        packagePurlVo.setVersion(externalPurlRef.getPkg().getVersion());
        packagePurlVo.setSupplier(externalPurlRef.getPkg().getSupplier());
        packagePurlVo.setDescription(externalPurlRef.getPkg().getDescription());
        packagePurlVo.setCopyright(externalPurlRef.getPkg().getCopyright());
        packagePurlVo.setSummary(externalPurlRef.getPkg().getSummary());
        packagePurlVo.setHomepage(externalPurlRef.getPkg().getHomepage());
        packagePurlVo.setSpdxId(externalPurlRef.getPkg().getSpdxId());
        packagePurlVo.setDownloadLocation(externalPurlRef.getPkg().getDownloadLocation());
        packagePurlVo.setFilesAnalyzed(externalPurlRef.getPkg().isFilesAnalyzed());
        packagePurlVo.setLicenseConcluded(externalPurlRef.getPkg().getLicenseConcluded());
        packagePurlVo.setLicenseDeclared(externalPurlRef.getPkg().getLicenseDeclared());
        packagePurlVo.setSourceInfo(externalPurlRef.getPkg().getSourceInfo());
        packagePurlVo.setSbomId(externalPurlRef.getPkg().getSbom().getId().toString());
        packagePurlVo.setPurl(PurlUtil.canonicalizePurl(externalPurlRef.getPurl()));

        return packagePurlVo;
    }

    private PackageWithStatisticsVo packageWithStatisticsVoFromPackage(Package pkg) {
        var vo = new PackageWithStatisticsVo();
        vo.setId(pkg.getId());
        vo.setName(pkg.getName());
        vo.setVersion(pkg.getVersion());
        vo.setLicenses(pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).map(LicenseVo::fromLicense).toList());
        vo.setCopyright(pkg.getCopyright());
        vo.setSupplier(pkg.getSupplier());
        vo.setStatistics(PackageStatisticsVo.fromPackage(pkg));
        return vo;
    }

    private Page<ExternalPurlRef> queryPackageInfoByBinaryFromDB(ExternalPurlRefCondition condition, Pageable pageable) {
        if (StringUtils.equalsIgnoreCase(condition.getBinaryType(), ReferenceCategory.RELATIONSHIP_MANAGER.name())) {
            return externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);
        } else {
            if (pageable == null) {
                pageable = PageRequest.of(0, SbomConstants.MAX_PAGE_SIZE);
            }
            return externalPurlRefRepository.findAll(ExternalPurlRefSpecs.convertCondition(condition), pageable);
        }
    }

    private List<ExternalPurlRef> filterVersionRange(ExternalPurlRefCondition condition, List<ExternalPurlRef> result) {
        List<ExternalPurlRef> returnResult;
        // 上下限均非空，startVersion <= version <= endVersion
        if (StringUtils.isNotEmpty(condition.getStartVersion()) && StringUtils.isNotEmpty(condition.getEndVersion())) {
            returnResult = result.stream()
                    .filter(ref -> VersionUtil.inRange(ref.getPurl().getVersion(), condition.getStartVersion(), condition.getEndVersion()))
                    .toList();
            // 下限为空，上限非空，version <= endVersion
        } else if (StringUtils.isEmpty(condition.getStartVersion())) {
            returnResult = result.stream()
                    .filter(ref -> VersionUtil.lessThanOrEqualTo(ref.getPurl().getVersion(), condition.getEndVersion()))
                    .toList();
            // 上限为空，下限非空，startVersion <= version
        } else {
            returnResult = result.stream()
                    .filter(ref -> VersionUtil.greaterThanOrEqualTo(ref.getPurl().getVersion(), condition.getStartVersion()))
                    .toList();
        }
        return returnResult;
    }

    private <T> List<T> pageList(List<T> list, Pageable pageable) {
        if (pageable.getOffset() >= list.size()) {
            return new ArrayList<>();
        }

        if (pageable.getOffset() + pageable.getPageSize() > list.size()) {
            return list.subList((int) pageable.getOffset(), list.size());
        }

        return list.subList((int) pageable.getOffset(), (int) pageable.getOffset() + pageable.getPageSize());
    }

    @Override
    public List<String> queryProductType() {
        return productTypeRepository.findAll().stream().map(ProductType::getType).toList();
    }

    @Override
    public ProductConfigVo queryProductConfigByProductType(String productType) {
        return productConfigCache.queryProductConfigByProductType(productType);
    }

    public Product queryProductByFullAttributes(Map<String, String> attributes) throws JsonProcessingException {
        String attr = Mapper.objectMapper.writeValueAsString(attributes);
        return productRepository.queryProductByFullAttributes(attr);
    }

    @Override
    public void persistSbomFromTraceData(String productName, String fileName, InputStream inputStream) throws IOException {
        byte[] sbomContent = traceDataAnalyzer.analyze(productName, inputStream);
        readSbomFile(productName, productName + ".spdx.json", sbomContent);
    }

    @Override
    public ProductStatistics queryProductStatistics(String productName) {
        return productStatisticsRepository.findNewestByProductName(productName);
    }

    @Override
    public List<VulCountVo> queryProductVulTrend(String productName, Long startTimestamp, Long endTimestamp) {
        Long oneMonthInMilli = 30L * 24 * 60 * 60 * 1000;
        // if endTimestamp is not set, set it to now
        if (endTimestamp == 0) {
            endTimestamp = System.currentTimeMillis();
        }
        // if startTimestamp is not set, set it to one month before endTimestamp
        if (startTimestamp == 0) {
            startTimestamp = endTimestamp - oneMonthInMilli;
        }
        return productStatisticsRepository.findByProductNameAndCreateTimeRange(productName, startTimestamp, endTimestamp)
                .stream()
                .map(VulCountVo::fromProductStatistics)
                .toList();
    }

    @Override
    public PackageStatisticsVo queryPackageStatisticsByPackageId(String packageId) {
        return packageRepository.findById(UUID.fromString(packageId)).map(PackageStatisticsVo::fromPackage).orElse(null);
    }

    @Override
    public List<LicenseVo> queryLicenseByPackageId(String packageId) {
        List<License> result = licenseRepository.findByPkgId(UUID.fromString(packageId));
        return result.stream().map(LicenseVo::fromLicense).toList();
    }

    public PageVo<LicenseVo> queryLicense(String productName, String license, Boolean isLegal, Pageable pageable) throws Exception {
        Page<Map> result = licenseRepository.findUniversal(productName, license, isLegal, pageable);
        return new PageVo<>((PageImpl<LicenseVo>) EntityUtil.castEntity(result, LicenseVo.class));
    }

    @Override
    public List<CopyrightVo> queryCopyrightByPackageId(String packageId) {
        CopyrightVo copyrightVo = new CopyrightVo();
        Package pkg = packageRepository.findById(UUID.fromString(packageId)).orElse(new Package());
        String copyright = pkg.getCopyright();
        if (copyright == null) {
            logger.debug("can not get copyright for package {}.", pkg.getId());
            return List.of(new CopyrightVo());
        }
        String pattern = SbomConstants.COPYRIGHT_REGULAR_EXPRESSION;
        Pattern r = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Matcher m = r.matcher(copyright);
        if (m.find()) {
            String organization = cleanRegex(m.group(5));
            String startYear = cleanRegex(m.group(3)).split("\\W")[0];

            copyrightVo.setOrganization(organization);
            copyrightVo.setStartYear(startYear);
            copyrightVo.setAdditionalInfo(copyright);
        } else {
            logger.error("copyright of package:{} can not match regular expression, copyright:{}.", pkg.getId(), copyright);
        }
        return List.of(copyrightVo);
    }

    public String cleanRegex(String s) {
        String pattern = "^\\W*|\\W*$";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(s);
        s = m.replaceAll("");
        return s;
    }

    @Override
    public PageVo<VulnerabilityVo> queryPackageVulnerability(String packageId, String severity, String vulId, Pageable pageable) {
        Page<ExternalVulRef> result = externalVulRefRepository.findByPackageIdAndSeverityAndVulId(UUID.fromString(packageId), severity, vulId, pageable);
        return new PageVo<>(new PageImpl<>(result.stream().map(this::fromExternalVulRef).toList(),
                result.getPageable(),
                result.getTotalElements()));
    }

    private VulnerabilityVo fromExternalVulRef(ExternalVulRef externalVulRef) {
        VulnerabilityVo vo = new VulnerabilityVo();

        Vulnerability vulnerability = externalVulRef.getVulnerability();
        vo.setVulId(vulnerability.getVulId());
        VulnerabilityVo.inferAndSetScore(vo, vulnerability);
        vo.setReferences(vulnerability.getVulReferences().stream().map(ref -> Pair.of(ref.getSource(), ref.getUrl())).toList());
        vo.setPurl(PurlUtil.canonicalizePurl(externalVulRef.getPurl()));
        return vo;
    }

    @Override
    public PageVo<VulnerabilityVo> queryVulnerability(String productName, String packageId, String severity, String vulId, Pageable pageable) {
        Page<Vulnerability> result = vulnerabilityRepository.findByProductNameAndPackageIdAndSeverityAndVulId(
                productName, Objects.isNull(packageId) ? null : UUID.fromString(packageId), severity, vulId, pageable);
        return new PageVo<>(new PageImpl<>(result.stream().map(VulnerabilityVo::fromVulnerability).toList(),
                result.getPageable(),
                result.getTotalElements()));
    }

    @Override
    public Graph queryVulImpact(String productName, String vulId) {
        var graph = new Graph();
        var refs = externalVulRefRepository.findByProductNameAndVulId(productName, vulId);
        if (ObjectUtils.isEmpty(refs)) {
            return graph;
        }

        var vulNode = graph.createVulNode(vulId);
        graph.addNode(vulNode);

        refs.forEach(ref -> {
            var directPurlRef = ref.getPkg().getExternalPurlRefs().stream()
                    .filter(purlRef -> purlRef.getPurl().equals(ref.getPurl()))
                    .findFirst()
                    .orElseThrow();
            var packagePurlRef = ref.getPkg().getExternalPurlRefs().stream()
                    .filter(purlRef -> StringUtils.equals(purlRef.getCategory(), ReferenceCategory.PACKAGE_MANAGER.name()))
                    .findFirst()
                    .orElseThrow();

            Node packageNode;
            if (StringUtils.equals(directPurlRef.getCategory(), ReferenceCategory.PACKAGE_MANAGER.name())) {
                packageNode = graph.createPackageNode(PurlUtil.canonicalizePurl(directPurlRef.getPurl()), directPurlRef.getPkg().getId().toString());
                if (graph.nodeVisited(packageNode)) {
                    return;
                }
                graph.addNode(packageNode);
                graph.addEdge(new Edge(vulNode.getId(), packageNode.getId()));
                extractTransitiveDepRecursively(graph, packagePurlRef, packageNode);
            } else {
                var directNode = graph.createDepNode(PurlUtil.canonicalizePurl(directPurlRef.getPurl()), directPurlRef.getPkg().getId().toString());
                if (graph.nodeVisited(directNode)) {
                    return;
                }
                graph.addNode(directNode);
                graph.addEdge(new Edge(vulNode.getId(), directNode.getId()));

                packageNode = graph.createPackageNode(PurlUtil.canonicalizePurl(packagePurlRef.getPurl()), packagePurlRef.getPkg().getId().toString());
                graph.addEdge(new Edge(directNode.getId(), packageNode.getId()));
                if (graph.nodeVisited(packageNode)) {
                    return;
                }
                graph.addNode(packageNode);
                extractTransitiveDepRecursively(graph, packagePurlRef, packageNode);
            }
        });
        return graph;
    }

    private void extractTransitiveDepRecursively(Graph graph, ExternalPurlRef startRef, Node startNode) {
        var transitiveDepSpdxIds = startRef.getPkg().getSbom().getSbomElementRelationships().stream()
                .filter(it -> StringUtils.equals(it.getRelatedElementId(), startRef.getPkg().getSpdxId()))
                .map(SbomElementRelationship::getElementId)
                .toList();
        if (ObjectUtils.isEmpty(transitiveDepSpdxIds)) {
            return;
        }
        startRef.getPkg().getSbom().getPackages().stream()
                .filter(pkg -> transitiveDepSpdxIds.contains(pkg.getSpdxId()))
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .filter(ref -> StringUtils.equals(ref.getCategory(), ReferenceCategory.PACKAGE_MANAGER.name()))
                .forEach(ref -> {
                    var node = graph.createTransitiveDepNode(PurlUtil.canonicalizePurl(ref.getPurl()), startNode.getY(), ref.getPkg().getId().toString());
                    if (graph.nodeVisited(node)) {
                        return;
                    }
                    graph.addNode(node);
                    graph.addEdge(new Edge(startNode.getId(), node.getId()));
                    startNode.setSize(startNode.getSize() + 1);
                    extractTransitiveDepRecursively(graph, ref, node);
                });
    }

    @Override
    public void addProduct(AddProductRequest req) {
        if (Arrays.stream(addableProductTypes).noneMatch(it -> StringUtils.equals(it, req.getProductType()))) {
            throw new RuntimeException("not allowed to add product with type [%s]".formatted(req.getProductType()));
        }

        productTypeRepository.lockTable();
        productTypeRepository.findById(req.getProductType()).orElseThrow(
                () -> new RuntimeException("invalid productType: %s, valid types: %s".formatted(req.getProductType(), queryProductType())));

        productRepository.findByName(req.getProductName()).ifPresent(product -> {
            throw new RuntimeException("product [%s] already exists".formatted(req.getProductName()));
        });

        Map<String, ProductConfig> productConfigs = productConfigRepository.findByProductTypeOrderByOrdAsc(req.getProductType())
                .stream().collect(Collectors.toMap(ProductConfig::getName, Function.identity()));
        Set<String> productConfigNames = productConfigs.values().stream().map(ProductConfig::getName).collect(Collectors.toSet());
        if (!productConfigNames.containsAll(req.getAttribute().keySet())) {
            throw new RuntimeException("invalid attribute keys, valid keys: %s".formatted(productConfigNames));
        }

        if (req.getAttribute().values().stream().anyMatch(it -> StringUtils.isBlank(it.getValue()) || StringUtils.isBlank(it.getLabel()))) {
            throw new RuntimeException("there exists blank values or labels in attribute");
        }

        req.getAttribute().forEach((key, value) -> productConfigs.get(key).getProductConfigValues().forEach(it -> {
            if (StringUtils.equals(it.getValue(), value.getValue()) && !StringUtils.equals(it.getLabel(), value.getLabel())) {
                throw new RuntimeException("the label of value [%s] already exists, it is [%s], not [%s]".formatted(value.getValue(), it.getLabel(), value.getLabel()));
            }
            if (StringUtils.equals(it.getLabel(), value.getLabel()) && !StringUtils.equals(it.getValue(), value.getValue())) {
                throw new RuntimeException("the value of label [%s] already exists, it is [%s], not [%s]".formatted(value.getLabel(), it.getValue(), value.getValue()));
            }
        }));

        Map<String, String> productAttribute = req.getAttribute().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().getValue()));
        productAttribute.put("productType", req.getProductType());
        String attr;
        try {
            attr = Mapper.objectMapper.writeValueAsString(productAttribute);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("attribute is not a valid json object");
        }
        Optional.ofNullable(productRepository.queryProductByFullAttributes(attr)).ifPresent(product -> {
            throw new RuntimeException("product with attribute [%s] already exists, its name is [%s]".formatted(req.getAttribute(), product.getName()));
        });

        req.getAttribute().forEach((key, value) -> {
            if (productConfigs.get(key).getProductConfigValues().stream()
                    .noneMatch(it -> StringUtils.equals(it.getValue(), value.getValue()) && StringUtils.equals(it.getLabel(), value.getLabel()))) {
                ProductConfigValue productConfigValue = new ProductConfigValue();
                productConfigValue.setProductConfig(productConfigs.get(key));
                productConfigValue.setValue(value.getValue());
                productConfigValue.setLabel(value.getLabel());
                productConfigs.get(key).addProductConfigValue(productConfigValue);
                productConfigRepository.save(productConfigs.get(key));
            }
        });

        Product product = new Product();
        product.setName(req.getProductName());
        product.setAttribute(productAttribute);
        productRepository.save(product);
    }

    @Override
    public byte[] writePackageSbom(String productName, String pkgName, String pkgVersion,
                                   String spec, String specVersion, String format) throws IOException {
        format = StringUtils.lowerCase(format);
        spec = StringUtils.lowerCase(spec);

        if (!SbomFormat.EXT_TO_FORMAT.containsKey(format)) {
            throw new RuntimeException("sbom file format: %s is not support".formatted(format));
        }

        SbomSpecification sbomSpec = SbomSpecification.findSpecification(spec, specVersion);
        if (!SbomSpecification.CYCLONEDX_1_4.equals(sbomSpec)) {
            throw new RuntimeException("sbom file specification: %s - %s is not support".formatted(spec, specVersion));
        }

        SbomWriter sbomWriter = SbomApplicationContextHolder.getSbomWriter(sbomSpec.getSpecification());
        return sbomWriter.writePackage(productName, pkgName, pkgVersion, SbomFormat.EXT_TO_FORMAT.get(format));
    }

    @Override
    public byte[] writeAllPackageSbom(String productName, String originSpec, String specVersion, String originFormat)
            throws IOException {
        var format = StringUtils.lowerCase(originFormat);
        var spec = StringUtils.lowerCase(originSpec);

        if (!SbomFormat.EXT_TO_FORMAT.containsKey(format)) {
            throw new RuntimeException("sbom file format: %s is not support".formatted(format));
        }

        SbomSpecification sbomSpec = SbomSpecification.findSpecification(spec, specVersion);
        if (!SbomSpecification.CYCLONEDX_1_4.equals(sbomSpec)) {
            throw new RuntimeException("sbom file specification: %s - %s is not support".formatted(spec, specVersion));
        }

        SbomWriter sbomWriter = SbomApplicationContextHolder.getSbomWriter(sbomSpec.getSpecification());
        Sbom sbom = sbomRepository.findByProductName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's sbom metadata".formatted(productName)));
        var nameToSbom = sbom.getPackages().stream().collect(Collectors.toMap(
                pkg -> "%s-%s-%s-%s-sbom.%s".formatted(productName.replace("/", "_").replace("\\", "_"),
                        pkg.getName(), pkg.getVersion(), spec, format),
                pkg -> {
                    try {
                        return sbomWriter.writePackage(productName, pkg.getName(), pkg.getVersion(), SbomFormat.EXT_TO_FORMAT.get(format));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }));
        return FileUtil.tarBytes(nameToSbom);
    }
}
