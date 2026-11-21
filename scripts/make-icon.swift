// Renders the CVEScout app icon (shield + magnifying glass) into an .iconset folder.
// Usage: swift scripts/make-icon.swift <output.iconset>   then: iconutil -c icns <output.iconset>
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset")
try? FileManager.default.removeItem(at: output)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

/// Draws the icon on a 1024×1024 canvas (origin bottom-left).
func draw(in ctx: CGContext) {
    let space = CGColorSpaceCreateDeviceRGB()

    // Body: macOS icon grid – 824 pt rounded square with soft shadow.
    let body = CGRect(x: 100, y: 100, width: 824, height: 824)
    let bodyPath = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: color(0x000000, 0.35))
    ctx.addPath(bodyPath)
    ctx.setFillColor(color(0x0F172A))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(bodyPath)
    ctx.clip()
    let bg = CGGradient(colorsSpace: space, colors: [color(0x2563EB), color(0x0B1F4D)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
    ctx.restoreGState()

    // Shield
    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: 512, y: 815))
    shield.addCurve(to: CGPoint(x: 752, y: 735), control1: CGPoint(x: 600, y: 770), control2: CGPoint(x: 680, y: 745))
    shield.addLine(to: CGPoint(x: 752, y: 520))
    shield.addCurve(to: CGPoint(x: 512, y: 205), control1: CGPoint(x: 752, y: 370), control2: CGPoint(x: 640, y: 265))
    shield.addCurve(to: CGPoint(x: 272, y: 520), control1: CGPoint(x: 384, y: 265), control2: CGPoint(x: 272, y: 370))
    shield.addLine(to: CGPoint(x: 272, y: 735))
    shield.addCurve(to: CGPoint(x: 512, y: 815), control1: CGPoint(x: 344, y: 745), control2: CGPoint(x: 424, y: 770))
    shield.closeSubpath()

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 20, color: color(0x000000, 0.3))
    ctx.addPath(shield)
    ctx.setFillColor(color(0xFFFFFF))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shield)
    ctx.clip()
    let sg = CGGradient(colorsSpace: space, colors: [color(0xFFFFFF), color(0xDCE7F7)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(sg, start: CGPoint(x: 512, y: 815), end: CGPoint(x: 512, y: 205), options: [])
    ctx.restoreGState()

    // Magnifying glass inside the shield
    let lensCenter = CGPoint(x: 490, y: 540)
    let lensRadius: CGFloat = 105
    ctx.setLineCap(.round)
    ctx.setStrokeColor(color(0x1E3A8A))
    ctx.setLineWidth(46)
    ctx.move(to: CGPoint(x: lensCenter.x + lensRadius * 0.72, y: lensCenter.y - lensRadius * 0.72))
    ctx.addLine(to: CGPoint(x: 640, y: 380))
    ctx.strokePath()

    ctx.setFillColor(color(0xBFDBFE))
    ctx.fillEllipse(in: CGRect(x: lensCenter.x - lensRadius, y: lensCenter.y - lensRadius,
                               width: lensRadius * 2, height: lensRadius * 2))
    ctx.setLineWidth(36)
    ctx.strokeEllipse(in: CGRect(x: lensCenter.x - lensRadius, y: lensCenter.y - lensRadius,
                                 width: lensRadius * 2, height: lensRadius * 2))

    // Accent: orange "finding" dot inside the lens
    ctx.setFillColor(color(0xF97316))
    ctx.fillEllipse(in: CGRect(x: lensCenter.x - 30, y: lensCenter.y - 30, width: 60, height: 60))
}

let sizes: [(name: String, px: Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
for (name, px) in sizes {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!.cgContext
    ctx.interpolationQuality = .high
    ctx.scaleBy(x: CGFloat(px) / 1024, y: CGFloat(px) / 1024)
    draw(in: ctx)
    try rep.representation(using: .png, properties: [:])!.write(to: output.appendingPathComponent("\(name).png"))
}
print("✔ \(output.path)")
