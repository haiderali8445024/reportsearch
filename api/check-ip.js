export default async function handler(req, res) {
  try {
    // Visitor IP
    const forwarded = req.headers["x-forwarded-for"];
    const ip =
      (forwarded ? forwarded.split(",")[0].trim() : null) ||
      req.headers["x-real-ip"] ||
      req.socket?.remoteAddress ||
      "";

    // Local/dev IPs
    const cleanIp = ip.replace("::ffff:", "");

    if (
      !cleanIp ||
      cleanIp === "127.0.0.1" ||
      cleanIp === "::1"
    ) {
      return res.status(200).json({
        allowed: true,
        vpn: false,
        proxy: false,
        tor: false,
        datacenter: false,
        risk: 0,
        note: "Local/test IP"
      });
    }

    const apiKey = process.env.IPQS_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        allowed: false,
        error: "IPQS_API_KEY is not configured"
      });
    }

    const url =
      `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(apiKey)}/${encodeURIComponent(cleanIp)}` +
      `?strictness=1&allow_public_access_points=true&fast=true`;

    const response = await fetch(url);

    if (!response.ok) {
      return res.status(502).json({
        allowed: false,
        error: "IP verification service unavailable"
      });
    }

    const data = await response.json();

    if (!data.success) {
      return res.status(502).json({
        allowed: false,
        error: data.message || "IP verification failed"
      });
    }

    const vpn = data.vpn === true;
    const proxy = data.proxy === true;
    const tor = data.tor === true;
    const datacenter = data.active_vpn === true || data.host === true;

    // Block VPN, proxy and Tor.
    const blocked = vpn || proxy || tor;

    return res.status(200).json({
      allowed: !blocked,
      vpn,
      proxy,
      tor,
      datacenter,
      risk: data.fraud_score ?? 0,
      country: data.country_code || null,
      city: data.city || null
    });

  } catch (error) {
    console.error("IP check error:", error);

    return res.status(500).json({
      allowed: false,
      error: "Unable to verify visitor"
    });
  }
}
