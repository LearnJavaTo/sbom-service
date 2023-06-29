package org.opensourceway.sbom.api.writer;


import org.opensourceway.sbom.model.enums.SbomFormat;

import java.io.IOException;

public interface SbomWriter {
    byte[] write(String productName, SbomFormat format) throws IOException;

    byte[] writePackage(String productName, String pkgName, String pkgVersion, SbomFormat format) throws IOException;
}
