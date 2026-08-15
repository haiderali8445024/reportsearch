export default async function handler(req, res) {

  try {

    const apiKey = process.env.PROXYCHECK_API_KEY;

    if (!apiKey) {

      return res.status(500).json({
        allowed: false,
        reason: "Security configuration is missing."
      });

    }

    const forwarded =
      req.headers["x-forwarded-for"];

    const ip =
      (forwarded
        ? forwarded.split(",")[0].trim()
        : null) ||
      req.headers["x-real-ip"] ||
      req.socket?.remoteAddress ||
      "";

    const cleanIp =
      ip.replace("::ffff:", "").trim();

    if (!cleanIp) {

      return res.status(403).json({
        allowed: false,
        reason: "Unable to verify your connection."
      });

    }

    const apiUrl =
      `https://proxycheck.io/v2/${encodeURIComponent(cleanIp)}` +
      `?key=${encodeURIComponent(apiKey)}` +
      `&vpn=1` +
      `&asn=1` +
      `&risk=1`;

    const response =
      await fetch(apiUrl, {
        method: "GET",
        headers: {
          "Accept": "application/json"
        }
      });

    if (!response.ok) {

      return res.status(502).json({
        allowed: false,
        reason: "Connection verification service unavailable."
      });

    }

    const data =
      await response.json();

    if (
      !data ||
      data.status !== "ok"
    ) {

      return res.status(502).json({
        allowed: false,
        reason: "Unable to verify your connection."
      });

    }

    const result =
      data[cleanIp];

    if (!result) {

      return res.status(403).json({
        allowed: false,
        reason: "Unable to verify your connection."
      });

    }

    const isProxy =
      String(result.proxy || "").toLowerCase() === "yes";

    const isVpn =
      String(result.vpn || "").toLowerCase() === "yes";

    const risk =
      Number(result.risk || 0);

    const provider =
      String(result.provider || "").toLowerCase();

    const type =
      String(result.type || "").toLowerCase();

    /*
      Block clear proxy/VPN detections.
      High-risk connections are also blocked.
    */

    const highRisk =
      risk >= 75;

    const datacenter =
      type.includes("hosting") ||
      type.includes("business") ||
      provider.includes("digitalocean") ||
      provider.includes("ovh") ||
      provider.includes("hetzner") ||
      provider.includes("amazon") ||
      provider.includes("google cloud") ||
      provider.includes("microsoft");

    if (isProxy || isVpn) {

      return res.status(200).json({
        allowed: false,
        proxy: isProxy,
        vpn: isVpn,
        risk: risk,
        reason:
          "VPN or proxy connections are not supported."
      });

    }

    if (highRisk) {

      return res.status(200).json({
        allowed: false,
        proxy: isProxy,
        vpn: isVpn,
        risk: risk,
        reason:
          "This connection has been flagged as high risk."
      });

    }

    /*
      Datacenter detection is returned but not
      automatically blocked here to reduce
      false positives.
    */

    return res.status(200).json({
      allowed: true,
      proxy: false,
      vpn: false,
      datacenter: datacenter,
      risk: risk,
      country: result.isocode || null
    });

  } catch (error) {

    console.error(
      "ProxyCheck error:",
      error
    );

    return res.status(500).json({
      allowed: false,
      reason:
        "Unable to verify your connection."
    });
  }
}
