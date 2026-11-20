import Foundation

/// Matches a single NVD CVE record against the local inventory (used for CVE lists).
enum NVDMatching {
    static func normalized(_ s: String) -> String {
        s.lowercased().filter { $0.isLetter || $0.isNumber }
    }

    /// CPE products of the CVE that correspond to `item`.
    static func products(of cve: NVDCVE, for item: SoftwareItem) -> [CPEProduct] {
        let affected = cve.affectedProducts.compactMap { pair -> CPEProduct? in
            let p = pair.split(separator: ":", maxSplits: 1).map(String.init)
            return p.count == 2 ? CPEProduct(p[0], p[1]) : nil
        }
        return affected.filter { cpe in
            switch item.source {
            case .system:
                return cpe.vendor == "apple" && (cpe.product == "macos" || cpe.product == "mac_os_x" || cpe.product == "mac_os")
            case .application:
                if let curated = ProductCatalog.cpeProduct(for: item) { return curated == cpe }
                let name = normalized(item.name)
                let product = normalized(cpe.product)
                // "VLC" ↔ "vlc_media_player" is too loose; require equality, or vendor in bundle id plus name match.
                if name.count >= 4, product == name { return true }
                let vendor = normalized(cpe.vendor)
                return name.count >= 3 && vendor.count >= 3
                    && item.identifier.lowercased().contains(vendor) && product.hasPrefix(name)
            case .homebrew:
                let base = item.identifier.split(separator: "@").first.map { normalized(String($0)) } ?? ""
                return base.count >= 3 && normalized(cpe.product) == base
            }
        }
    }

    static func evaluate(cve: NVDCVE, inventory: [SoftwareItem], kev: KEVCatalog) -> CVECheckResult {
        var affected: [String] = [], checked: [String] = [], ranges: [String] = []
        for item in inventory {
            let candidates = products(of: cve, for: item)
            guard !candidates.isEmpty else { continue }
            var itemVersion = item.version
            if let curated = ProductCatalog.cpeProduct(for: item),
               let v = ProductCatalog.nvdVersion(for: item, product: curated) { itemVersion = v }
            guard let version = Version(itemVersion) else { continue }
            let label = "\(item.name) \(item.version)"
            if let hit = candidates.lazy.compactMap({ cve.match(vendor: $0.vendor, product: $0.product, version: version) }).first {
                affected.append(label)
                ranges.append(hit.rangeDescription)
            } else {
                checked.append(label)
            }
        }
        let status: CVEStatus
        if cve.affectedProducts.isEmpty { status = .unknown }           // not yet analysed by NVD
        else if !affected.isEmpty { status = .affected }
        else if !checked.isEmpty { status = .patched }
        else { status = .notInstalled }
        return CVECheckResult(
            cve: cve.id, status: status,
            advisories: [.init(id: cve.id, title: "NVD", url: cve.detailURL)],
            software: Array(Set(status == .affected ? affected : checked)).sorted(),
            matchedRanges: Array(Set(ranges)).sorted(),
            kev: kev.entries[cve.id],
            source: .nvd, summary: cve.summary, cvssScore: cve.baseScore
        )
    }
}
