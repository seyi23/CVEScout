import Foundation

/// Attribution required or requested by the data providers (see NOTICE.md).
public enum DataSources {
    /// Required wording of the NVD terms of use for products using the NVD API.
    public static let nvdNotice = "This product uses the NVD API but is not endorsed or certified by the NVD."

    public static let attribution = """
    Datenquellen: BSI WID/CERT-Bund (CSAF, TLP:WHITE), NIST National Vulnerability Database, \
    CISA Known Exploited Vulnerabilities Catalog. CVEScout ist mit keinem Herausgeber verbunden. \
    \(nvdNotice)
    """
}
