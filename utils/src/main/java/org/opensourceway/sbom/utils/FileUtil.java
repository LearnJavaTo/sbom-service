package org.opensourceway.sbom.utils;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class FileUtil {
    private static final Logger logger = LoggerFactory.getLogger(FileUtil.class);

    public static void extractTarGzipArchive(String file, String targetDir) throws IOException {
        extractTarGzipArchive(Paths.get(file), targetDir);
    }

    public static void extractTarGzipArchive(Path path, String targetDir) throws IOException {
        logger.info("extract '{}' to '{}'", path, targetDir);
        try (FileInputStream fis = new FileInputStream(path.toFile());
             BufferedInputStream bis = new BufferedInputStream(fis);
             GzipCompressorInputStream gis = new GzipCompressorInputStream(bis);
             TarArchiveInputStream tar = new TarArchiveInputStream(gis)) {

            extractTarArchiveInputStream(tar, targetDir);
        }
        logger.info("successfully extracted '{}' to '{}'", path, targetDir);
    }

    public static void extractTarGzipArchive(InputStream is, String targetDir) throws IOException {
        logger.info("extract from input stream to '{}'", targetDir);
        try (BufferedInputStream bis = new BufferedInputStream(is);
             GzipCompressorInputStream gis = new GzipCompressorInputStream(bis);
             TarArchiveInputStream tar = new TarArchiveInputStream(gis)) {

            extractTarArchiveInputStream(tar, targetDir);
        }
        logger.info("successfully extract from input stream to '{}'", targetDir);
    }

    private static void extractTarArchiveInputStream(TarArchiveInputStream tar, String targetDir) throws IOException {
        TarArchiveEntry entry;
        while ((entry = tar.getNextTarEntry()) != null) {
            if (!tar.canReadEntryData(entry)) {
                logger.warn("can't read data from entry '{}'", entry);
                continue;
            }
            File f = Paths.get(targetDir, entry.getName()).toFile();
            if (!f.toPath().normalize().startsWith(Paths.get(targetDir))) {
                throw new IOException("Bad tar entry: %s".formatted(f));
            }
            if (entry.isDirectory()) {
                ensureDirExists(f);
            } else {
                File parent = f.getParentFile();
                ensureDirExists(parent);
                try (OutputStream os = Files.newOutputStream(f.toPath())) {
                    IOUtils.copy(tar, os);
                }
            }
        }
    }

    public static void ensureDirExists(String dir) throws IOException {
        File file = Paths.get(dir).toFile();
        if (!file.isDirectory() && !file.mkdirs()) {
            throw new IOException("failed to create directory %s".formatted(dir));
        }
    }

    public static void ensureDirExists(File file) throws IOException {
        ensureDirExists(file.getCanonicalPath());
    }

    public static byte[] tarBytes(Map<String, byte[]> nameToData) throws IOException {
        var baos = new ByteArrayOutputStream();
        var bos = new BufferedOutputStream(baos);
        var gos = new GzipCompressorOutputStream(bos);
        var tar = new TarArchiveOutputStream(gos);
        try (baos; bos; gos; tar) {
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            for (Map.Entry<String, byte[]> e : nameToData.entrySet()) {
                var entry = new TarArchiveEntry(e.getKey());
                entry.setSize(e.getValue().length);
                tar.putArchiveEntry(entry);
                tar.write(e.getValue());
                tar.closeArchiveEntry();
            }
        }
        return baos.toByteArray();
    }
}
