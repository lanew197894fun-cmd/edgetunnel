// no-tunnel: 禁用 WebSocket / sockets / TCP 轉發，只保留 Admin + KV + HTTP 偽裝反代

const DEFAULT_PAGES = "https://edt-pages.github.io";
const KV_LIMIT_MB = 4;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ua = request.headers.get("User-Agent") || "null";
    const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();

    // 明確禁用 WS（no-tunnel）
    if (upgrade === "websocket") {
      return new Response("WebSocket disabled (no-tunnel)", { status: 403 });
    }
	// DIAG: 檢查 secrets 是否載入（不回明文）
	const diagPath = url.pathname.slice(1).toLowerCase();
	if (diagPath === "__diag") {
	const adminRaw = pickAdmin(env);
	const keyRaw = (env.KEY || "").trim();

	const out = {
    host: url.hostname,
    hasADMIN: !!adminRaw,
    hasKEY: !!keyRaw,
    adminLen: adminRaw ? String(adminRaw).length : 0,
    keyLen: keyRaw ? String(keyRaw).length : 0,
    adminHash: adminRaw ? await sha256Hex(String(adminRaw)) : null,
    keyHash: keyRaw ? await sha256Hex(String(keyRaw)) : null,
	};
	
	return new Response(JSON.stringify(out, null, 2), {
		status: 200,
		headers: { "Content-Type": "application/json;charset=utf-8" },
	});
	}

    // http -> https
    if (url.protocol === "http:") {
      return Response.redirect(
        url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`),
        301
      );
    }

    const admin = pickAdmin(env);
    const key = (env.KEY || "change-me").trim();
    const pages = (env.PAGES || DEFAULT_PAGES).trim();

    if (!admin) return fetchNoCache(`${pages}/noADMIN`, 404);
    if (!env.KV) return fetchNoCache(`${pages}/noKV`, 404);

    const host = pickHost(env, url.hostname);
    const userID = await pickUserID(env, admin, key);

    const pathLower = url.pathname.slice(1).toLowerCase();
    const pathRaw = url.pathname.slice(1);

    // /KEY -> /sub?token=...
    if (pathLower === key.toLowerCase() && key && key !== "change-me") {
      const params = new URLSearchParams(url.search);
      params.set("token", await sha256Hex(`${host}${userID}${key}`));
      return new Response("redirect", {
        status: 302,
        headers: { Location: `/sub?${params.toString()}` },
      });
    }

    // /login
    if (pathLower === "login") {
      return handleLogin(request, { ua, admin, key, pages });
    }

    // /logout
    if (pathLower === "logout") {
      const r = new Response("redirect", { status: 302, headers: { Location: "/login" } });
      r.headers.set("Set-Cookie", cookieAuth("", 0));
      return r;
    }

    // /locations（登入後）
    if (pathLower === "locations") {
      if (!(await isAuthed(request, { ua, admin, key }))) return new Response("Forbidden", { status: 403 });
      return fetch(new Request("https://speed.cloudflare.com/locations", {
        headers: { Referer: "https://speed.cloudflare.com/" }
      }));
    }

    // /admin 或 /admin/*
    if (pathLower === "admin" || pathLower.startsWith("admin/")) {
      if (!(await isAuthed(request, { ua, admin, key }))) {
        return new Response("redirect", { status: 302, headers: { Location: "/login" } });
      }

      let cfg = await readConfig(env, host, userID);

      if (pathLower === "admin/log.json") {
        const log = (await env.KV.get("log.json")) || "[]";
        return new Response(log, { status: 200, headers: { "Content-Type": "application/json;charset=utf-8" } });
      }

      if (pathLower === "admin/init") {
        const defaults = defaultConfig(host, userID);
        await env.KV.put("config.json", JSON.stringify(defaults, null, 2));
        cfg = await readConfig(env, host, userID);

        ctx.waitUntil(writeLog(env, request, "Init_Config"));
        cfg.init = "配置已重置为默认值";
        return json(cfg);
      }

      if (pathLower === "admin/config.json") {
        if (request.method === "POST") {
          const newCfg = await safeJson(request);
          if (!newCfg || !newCfg.UUID || !newCfg.HOST) return json({ error: "配置不完整" }, 400);

          const merged = deepMerge(cfg, newCfg);
          await env.KV.put("config.json", JSON.stringify(merged, null, 2));

          ctx.waitUntil(writeLog(env, request, "Save_Config"));
          return json({ success: true, message: "配置已保存" });
        }
        return json(cfg);
      }

      if (pathRaw === "admin/ADD.txt") {
        if (request.method === "POST") {
          const txt = await request.text();
          await env.KV.put("ADD.txt", txt);
          ctx.waitUntil(writeLog(env, request, "Save_Custom_IPs"));
          return json({ success: true, message: "ADD.txt 已保存" });
        } else {
          const txt = (await env.KV.get("ADD.txt")) || "null";
          return new Response(txt, { status: 200, headers: { "Content-Type": "text/plain;charset=utf-8" } });
        }
      }

      if (pathLower === "admin/cf.json") {
        if (request.method === "POST") {
          const o = await safeJson(request);
          await env.KV.put("cf.json", JSON.stringify(o || {}, null, 2));
          ctx.waitUntil(writeLog(env, request, "Save_CF"));
          return json({ success: true, message: "cf.json 已保存" });
        }
        return new Response((await env.KV.get("cf.json")) || "{}", {
          status: 200,
          headers: { "Content-Type": "application/json;charset=utf-8" }
        });
      }

      if (pathLower === "admin/tg.json") {
        if (request.method === "POST") {
          const o = await safeJson(request);
          await env.KV.put("tg.json", JSON.stringify(o || {}, null, 2));
          ctx.waitUntil(writeLog(env, request, "Save_TG"));
          return json({ success: true, message: "tg.json 已保存" });
        }
        return new Response((await env.KV.get("tg.json")) || "{}", {
          status: 200,
          headers: { "Content-Type": "application/json;charset=utf-8" }
        });
      }

      ctx.waitUntil(writeLog(env, request, "Admin_View"));
      return fetchNoCache(`${pages}/admin`, 200);
    }

    // /sub（no-tunnel：只回 config JSON）
    if (pathLower === "sub") {
      const token = url.searchParams.get("token") || "";
      const expect = await sha256Hex(`${host}${userID}${key}`);
      if (token !== expect) return new Response("无效的订阅TOKEN", { status: 403 });

      const cfg = await readConfig(env, host, userID);
      ctx.waitUntil(writeLog(env, request, "Get_SUB"));

      return json({
        success: true,
        host,
        userID,
        admin: `${url.protocol}//${url.host}/admin`,
        config: cfg,
      });
    }

    // 其餘：HTTP 偽裝反代（純 HTTP）
    return maskProxy(request, env, url, ua);
  },
};

// ---------------- helpers ----------------

function pickAdmin(env) {
  return env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
}

function pickHost(env, fallbackHost) {
  const raw = env.HOST ? String(env.HOST) : "";
  if (!raw.trim()) return fallbackHost;
  const arr = raw
    .split(/[\n,;\s]+/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(h => h.toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0]);
  return arr[0] || fallbackHost;
}

async function pickUserID(env, admin, key) {
  const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
  const envUUID = env.UUID || env.uuid;
  if (envUUID && uuidRegex.test(envUUID)) return String(envUUID).toLowerCase();

  const hex = await sha256Hex(`${admin}${key}`);
  return [hex.slice(0, 8), hex.slice(8, 12), "4" + hex.slice(13, 16), "8" + hex.slice(17, 20), hex.slice(20, 32)].join("-");
}

async function handleLogin(request, { ua, admin, key, pages }) {
  const cookies = request.headers.get("Cookie") || "";
  const authCookie = cookies.split(";").find(c => c.trim().startsWith("auth="))?.split("=")[1];

  const expect = await sha256Hex(`${ua}${key}${admin}`);
  if (authCookie === expect) return new Response("redirect", { status: 302, headers: { Location: "/admin" } });

  if (request.method === "POST") {
    const formData = await request.text();
    const params = new URLSearchParams(formData);
    const input = params.get("password") || "";
    if (input === admin) {
      const r = json({ success: true });
      r.headers.set("Set-Cookie", cookieAuth(expect, 86400));
      return r;
    }
    return json({ success: false }, 401);
  }

  return fetchNoCache(`${pages}/login`, 200);
}

async function isAuthed(request, { ua, admin, key }) {
  const cookies = request.headers.get("Cookie") || "";
  const authCookie = cookies.split(";").find(c => c.trim().startsWith("auth="))?.split("=")[1] || "";
  if (!authCookie) return false;
  const expect = await sha256Hex(`${ua}${key}${admin}`);
  return authCookie === expect;
}

function cookieAuth(val, maxAge) {
  return `auth=${val}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax; Secure`;
}

async function readConfig(env, host, userID) {
  const defaults = defaultConfig(host, userID);
  const txt = await env.KV.get("config.json");
  if (!txt) return defaults;
  try {
    const kvObj = JSON.parse(txt);
    return deepMerge(defaults, kvObj); // defaults 補欄位，不覆寫 KV 已有值
  } catch {
    return defaults;
  }
}

function defaultConfig(host, userID) {
  return {
    UUID: userID,
    HOST: host,
    HOSTS: [host],
    PATH: "/ws",
    CF: { Usage: { success: false, total: 0 } },
    TG: { 启用: false },
    优选订阅生成: { SUBNAME: "no-tunnel-config.json", SUBUpdateTime: 12 }
  };
}

function deepMerge(base, override) {
  if (Array.isArray(base) || Array.isArray(override)) return (override !== undefined) ? override : base;
  if (isObj(base) && isObj(override)) {
    const out = { ...base };
    for (const k of Object.keys(override)) out[k] = deepMerge(base[k], override[k]);
    return out;
  }
  return (override !== undefined) ? override : base;
}
function isObj(x) { return x && typeof x === "object" && !Array.isArray(x); }

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json;charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
async function safeJson(request) { try { return await request.json(); } catch { return null; } }

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function fetchNoCache(url, statusIfProxy = 200) {
  const r = await fetch(url);
  const headers = new Headers(r.headers);
  headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  headers.set("Pragma", "no-cache");
  headers.set("Expires", "0");
  return new Response(r.body, { status: statusIfProxy, statusText: r.statusText, headers });
}

// ---------------- logging ----------------

async function writeLog(env, request, type) {
  try {
    const entry = {
      TYPE: type,
      IP: request.headers.get("CF-Connecting-IP")
        || request.headers.get("X-Forwarded-For")
        || request.headers.get("X-Real-IP")
        || "Unknown",
      URL: request.url,
      UA: request.headers.get("User-Agent") || "Unknown",
      TIME: Date.now(),
    };

    let arr = [];
    const existing = await env.KV.get("log.json");
    if (existing) {
      try {
        arr = JSON.parse(existing);
        if (!Array.isArray(arr)) arr = [];
      } catch { arr = []; }
    }

    arr.push(entry);

    while (JSON.stringify(arr).length > KV_LIMIT_MB * 1024 * 1024 && arr.length > 0) {
      arr.shift();
    }

    await env.KV.put("log.json", JSON.stringify(arr, null, 2));
  } catch {
    // ignore
  }
}

// ---------------- http mask proxy ----------------

async function maskProxy(request, env, url, ua) {
  let target = env.URL || "nginx";

  if (target && target !== "nginx") {
    target = String(target).trim().replace(/\/$/, "");
    if (!/^https?:\/\//i.test(target)) target = "https://" + target;
    if (target.toLowerCase().startsWith("http://")) target = "https://" + target.substring(7);

    try {
      const u = new URL(target);
      target = `${u.protocol}//${u.host}`;
    } catch {
      target = "nginx";
    }
  }

  if (target === "nginx") {
    return new Response("<h1>nginx</h1>", { status: 200, headers: { "Content-Type": "text/html; charset=UTF-8" } });
  }

  try {
    const upstream = new URL(target);
    const h = new Headers(request.headers);

    h.set("Host", upstream.host);

    if (h.has("Referer")) {
      try {
        const r = new URL(h.get("Referer"));
        h.set("Referer", `${upstream.protocol}//${upstream.host}${r.pathname}${r.search}`);
      } catch {}
    }

    if (h.has("Origin")) h.set("Origin", `${upstream.protocol}//${upstream.host}`);
    if (!h.has("User-Agent") && ua && ua !== "null") h.set("User-Agent", ua);

    const method = request.method.toUpperCase();
    const init = {
      method,
      headers: h,
      cf: request.cf,
    };

    // GET/HEAD 不能帶 body；其他方法避免 body 被重複讀取
    if (method !== "GET" && method !== "HEAD") {
      init.body = request.clone().body;
    }

    return fetch(new Request(`${upstream.protocol}//${upstream.host}${url.pathname}${url.search}`, init));
  } catch {
    return new Response("<h1>nginx</h1>", { status: 200, headers: { "Content-Type": "text/html; charset=UTF-8" } });
  }
}
