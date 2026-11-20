@testable import CVEScoutCore
import Foundation
import Testing

@Suite("Version parsing and comparison")
struct VersionTests {
    @Test func parsesLenientStrings() {
        #expect(Version("142.0.7444.175")?.components == [142, 0, 7444, 175])
        #expect(Version("3.4.0_1")?.components == [3, 4, 0])
        #expect(Version("6.4.0 (12345)")?.components == [6, 4, 0])
        #expect(Version("v1.2")?.components == [1, 2])
        #expect(Version("128.5.0esr")?.components == [128, 5, 0])
        #expect(Version("abc") == nil)
    }

    @Test func comparesWithPadding() throws {
        #expect(try #require(Version("1.0")) == #require(Version("1.0.0")))
        #expect(try #require(Version("15.8.1")) < #require(Version("15.8.2")))
        #expect(try #require(Version("2026.10")) > #require(Version("2026.9.9")))
    }

    @Test func commonPrefix() throws {
        let v = try #require(Version("15.8.1"))
        #expect(v.commonPrefixLength(with: try #require(Version("15.8.2"))) == 2)
        #expect(v.commonPrefixLength(with: try #require(Version("26.7.2"))) == 0)
    }
}

@Suite("BSI version specs")
struct VersionSpecTests {
    @Test func simpleUpperBound() throws {
        let s = try #require(VersionSpec.parse("<2026.3"))
        #expect(s.label == "")
        #expect(s.matches(try #require(Version("2026.2.9"))))
        #expect(!s.matches(try #require(Version("2026.3"))))
    }

    @Test func labelledReleaseLine() throws {
        let s = try #require(VersionSpec.parse("Golden Gate <27.2"))
        #expect(s.label == "Golden Gate")
        #expect(s.upperBound == Version("27.2"))
    }

    @Test func exactVersionWithLabel() throws {
        let s = try #require(VersionSpec.parse("Tahoe 26.7.2"))
        #expect(s.exactVersion == Version("26.7.2"))
    }

    @Test func numbersInLabelAreIgnored() throws {
        let s = try #require(VersionSpec.parse("Office 2019 <16.78"))
        #expect(s.label == "Office 2019")
        #expect(s.constraints.count == 1)
    }

    @Test func rangesAndVers() throws {
        let a = try #require(VersionSpec.parse(">=1.0 <2.0"))
        let b = try #require(VersionSpec.parse("vers:generic/>=1.0|<2.0"))
        for s in [a, b] {
            #expect(s.matches(try #require(Version("1.5"))))
            #expect(!s.matches(try #require(Version("2.0"))))
            #expect(!s.matches(try #require(Version("0.9"))))
        }
    }

    @Test func foreignPlatforms() {
        #expect(Platform.isForeign("iOS <160.0"))
        #expect(Platform.isForeign("Android 3.7.2"))
        #expect(!Platform.isForeign("Golden Gate <27.2"))
        #expect(!Platform.isForeign("for macOS <2.1"))
        #expect(Platform.isMobileOnlyTitle("Mozilla Firefox für iOS: Mehrere Schwachstellen"))
        #expect(Platform.isMobileOnlyTitle("VLC für Android: Schwachstelle ermöglicht Manipulation"))
        #expect(Platform.isMobileOnlyTitle("Mozilla Firefox (iOS): Mehrere Schwachstellen"))
        #expect(!Platform.isMobileOnlyTitle("Apple iOS, iPadOS, macOS und Safari: Mehrere Schwachstellen"))
        #expect(!Platform.isMobileOnlyTitle("Mozilla Firefox und Thunderbird: Mehrere Schwachstellen"))
    }
}

@Suite("Affected evaluation")
struct EvaluatorTests {
    let macOSRanges = ["Golden Gate <27.2", "Tahoe <26.7.2", "Sequoia <15.8.2"].compactMap(VersionSpec.parse)
    let macOSFixed = ["27.2", "26.7.2", "15.8.2"].compactMap(Version.init)

    func affected(_ v: String, _ specs: [VersionSpec], _ fixed: [Version]) -> VersionSpec? {
        AffectedEvaluator.matchingSpec(installed: Version(v)!, affected: specs, fixed: fixed)
    }

    @Test func releaseLines() {
        #expect(affected("15.8.1", macOSRanges, macOSFixed)?.label == "Sequoia")
        #expect(affected("15.8.2", macOSRanges, macOSFixed) == nil)
        #expect(affected("26.7.2", macOSRanges, macOSFixed) == nil)
        #expect(affected("26.6", macOSRanges, macOSFixed)?.label == "Tahoe")
        #expect(affected("27.1", macOSRanges, macOSFixed)?.label == "Golden Gate")
        #expect(affected("27.2.1", macOSRanges, macOSFixed) == nil)
    }

    @Test func unlabelledLines() {
        let specs = ["<2026.3", "<2026.2.4"].compactMap(VersionSpec.parse)
        #expect(affected("2026.2.5", specs, []) == nil)
        #expect(affected("2026.1.0", specs, []) != nil)
        #expect(affected("2026.3", specs, []) == nil)
    }

    @Test func adobeYearScheme() {
        let specs = ["<2015.006.30527", "<2017.011.30175"].compactMap(VersionSpec.parse)
        #expect(affected("26.003.22110", specs, []) == nil)
        #expect(affected("15.006.30000", specs, []) != nil)
    }
}

@Suite("Plausibility of matches")
struct PlausibilityTests {
    func reason(_ installed: String, _ spec: String, _ refs: [String]) -> String? {
        AffectedEvaluator.implausibility(installed: Version(installed)!, matched: VersionSpec.parse(spec)!,
                                         references: refs.compactMap(Version.init))
    }

    @Test func differentProductSameName() {
        // Obsidian (notes, 1.x) vs. Obsidian Scheduler (<6.3.1)
        #expect(reason("1.15.1", "<6.3.1", ["6.3.1"]) != nil)
    }

    @Test func plausibleMatchesStayCertain() {
        #expect(reason("4.1.0", "<4.1.1", ["4.1.1"]) == nil)
        // An older macOS release line is still a real finding.
        #expect(reason("14.7", "Sequoia <15.8.2", ["15.8.2", "26.7.2", "27.2"]) == nil)
        #expect(reason("26.003.22110", "<2026.004", ["2026.004"]) == nil)
    }

    @Test func noFixVersion() {
        #expect(reason("9.0.2", ">=2.7", []) != nil)
    }

    @Test func dataQuirks() {
        #expect(VersionSpec.parse("commit 4da9812") == nil)
        #expect(VersionSpec.parse("=>1.11")?.constraints.first?.op == .ge)
    }
}
