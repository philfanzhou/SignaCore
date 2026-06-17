using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

// ============================================================
// JwksProbe — 端到端诊断: 登录 → 获取 token → JWKS → 验证
// 用法: JwksProbe [docretrieval-url] [identity-url] [username] [password]
// 默认: JwksProbe http://192.168.56.5:5012 http://192.168.56.5:10891 admin Qwer1234
// ============================================================

var baseUrl = args.Length > 0 ? args[0] : "http://192.168.56.5:5012";
var identityUrl = args.Length > 1 ? args[1] : "http://192.168.56.5:10891";
var username = args.Length > 2 ? args[2] : "admin";
var password = args.Length > 3 ? args[3] : "Qwer1234";

var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
var ok = true;

Console.WriteLine("=== JwksProbe 端到端诊断 ===");
Console.WriteLine($"DocRetrieval: {baseUrl}");
Console.WriteLine($"Identity:     {identityUrl}");
Console.WriteLine($"用户:         {username}");
Console.WriteLine();

// ---------- Step 1: 登录 ----------
Console.WriteLine("[1/4] 登录 DocRetrieval...");
string? accessToken = null;
try
{
    var loginBody = JsonSerializer.Serialize(new { username, password });
    var loginReq = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/admin/auth/login")
    {
        Content = new StringContent(loginBody, Encoding.UTF8, "application/json")
    };
    var sw = Stopwatch.StartNew();
    var loginResp = await client.SendAsync(loginReq);
    var loginJson = await loginResp.Content.ReadAsStringAsync();
    sw.Stop();

    Console.WriteLine($"  状态码: {(int)loginResp.StatusCode} {loginResp.StatusCode}");
    Console.WriteLine($"  耗时: {sw.ElapsedMilliseconds}ms");

    if (!loginResp.IsSuccessStatusCode)
    {
        Console.WriteLine($"  ❌ 登录失败! 响应: {loginJson[..Math.Min(300, loginJson.Length)]}");
        ok = false;
    }
    else
    {
        var doc = JsonDocument.Parse(loginJson);
        var root = doc.RootElement;
        var success = root.TryGetProperty("success", out var s) && s.GetBoolean();
        if (!success)
        {
            Console.WriteLine($"  ❌ 登录返回 success=false: {loginJson[..Math.Min(300, loginJson.Length)]}");
            ok = false;
        }
        else if (root.TryGetProperty("data", out var data))
        {
            accessToken = data.TryGetProperty("accessToken", out var t) ? t.GetString() : null;
            var expiresIn = data.TryGetProperty("expiresIn", out var e) ? e.GetInt32() : 0;
            var expiresAt = data.TryGetProperty("expiresAt", out var ea) ? ea.GetInt64() : 0;
            Console.WriteLine($"  ✅ 登录成功");
            Console.WriteLine($"  accessToken 长度: {accessToken?.Length ?? 0}");
            Console.WriteLine($"  expiresIn: {expiresIn}s, expiresAt: {expiresAt}");

            if (data.TryGetProperty("userInfo", out var userInfo))
            {
                var userId = userInfo.TryGetProperty("userId", out var uid) ? uid.GetString() : "";
                var uname = userInfo.TryGetProperty("username", out var un) ? un.GetString() : "";
                Console.WriteLine($"  用户: {uname} (id={userId})");
            }
        }
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  ❌ 登录异常: {ex.GetType().Name}: {ex.Message}");
    if (ex.InnerException != null)
        Console.WriteLine($"     Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
    ok = false;
}

// ---------- Step 2: JWKS ----------
Console.WriteLine();
Console.WriteLine("[2/4] 获取 JWKS...");
var jwksKeys = new List<(string Kid, string Alg)>();
try
{
    var jwksUrl = $"{identityUrl}/.well-known/jwks";
    var sw = Stopwatch.StartNew();
    var jwksResp = await client.GetAsync(jwksUrl);
    var jwksBody = await jwksResp.Content.ReadAsStringAsync();
    sw.Stop();

    Console.WriteLine($"  状态码: {(int)jwksResp.StatusCode} {jwksResp.StatusCode}");
    Console.WriteLine($"  耗时: {sw.ElapsedMilliseconds}ms");

    if (!jwksResp.IsSuccessStatusCode)
    {
        Console.WriteLine($"  ❌ JWKS 获取失败!");
        ok = false;
    }
    else
    {
        var doc = JsonDocument.Parse(jwksBody);
        if (doc.RootElement.TryGetProperty("keys", out var keys))
        {
            foreach (var key in keys.EnumerateArray())
            {
                var kid = key.TryGetProperty("kid", out var k) ? k.GetString() ?? "" : "";
                var alg = key.TryGetProperty("alg", out var a) ? a.GetString() ?? "" : "";
                jwksKeys.Add((kid, alg));
                Console.WriteLine($"  密钥: kid={kid}, alg={alg}");
            }
            Console.WriteLine($"  ✅ 共 {jwksKeys.Count} 个密钥");
        }
        else
        {
            Console.WriteLine($"  ❌ JWKS JSON 缺少 keys 字段");
            ok = false;
        }
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  ❌ JWKS 异常: {ex.GetType().Name}: {ex.Message}");
    if (ex.InnerException != null)
        Console.WriteLine($"     Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
    ok = false;
}

// ---------- Step 3: 解码 JWT ----------
Console.WriteLine();
Console.WriteLine("[3/4] 解码 JWT Token...");
string? tokenKid = null;
string? tokenIss = null;
string? tokenAud = null;
long tokenExp = 0;

if (string.IsNullOrEmpty(accessToken))
{
    Console.WriteLine("  ⚠️ 无 token，跳过");
}
else
{
    try
    {
        var parts = accessToken.Split('.');
        if (parts.Length != 3)
        {
            Console.WriteLine($"  ❌ JWT 格式错误: {parts.Length} 段");
            ok = false;
        }
        else
        {
            // Header
            var headerJson = Base64UrlDecode(parts[0]);
            var headerDoc = JsonDocument.Parse(headerJson);
            var headerRoot = headerDoc.RootElement;
            var headerAlg = headerRoot.TryGetProperty("alg", out var ha) ? ha.GetString() : "";
            tokenKid = headerRoot.TryGetProperty("kid", out var hk) ? hk.GetString() : null;
            Console.WriteLine($"  Header: alg={headerAlg}, kid={tokenKid ?? "(无)"}");

            // Payload
            var payloadJson = Base64UrlDecode(parts[1]);
            var payloadDoc = JsonDocument.Parse(payloadJson);
            var payloadRoot = payloadDoc.RootElement;

            tokenIss = payloadRoot.TryGetProperty("iss", out var i) ? i.GetString() : null;
            tokenAud = payloadRoot.TryGetProperty("aud", out var a) ? a.ToString().Trim('"') : null;
            tokenExp = payloadRoot.TryGetProperty("exp", out var e) ? e.GetInt64() : 0;

            Console.WriteLine($"  iss: {tokenIss ?? "(无)"}");
            Console.WriteLine($"  aud: {tokenAud ?? "(无)"}");
            if (tokenExp > 0)
            {
                var expTime = DateTimeOffset.FromUnixTimeSeconds(tokenExp);
                var remaining = expTime - DateTimeOffset.UtcNow;
                Console.WriteLine($"  exp: {expTime:yyyy-MM-dd HH:mm:ss} UTC (剩余 {remaining.TotalMinutes:F1} 分钟)");
            }

            // 其他 claims
            foreach (var claim in payloadRoot.EnumerateObject())
            {
                if (claim.Name is "iss" or "aud" or "exp" or "nbf" or "iat") continue;
                Console.WriteLine($"  {claim.Name}: {claim.Value}");
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  ❌ JWT 解码失败: {ex.Message}");
        ok = false;
    }
}

// ---------- Step 4: 调用受保护 API ----------
Console.WriteLine();
Console.WriteLine("[4/4] 调用 /admin/documents...");
if (string.IsNullOrEmpty(accessToken))
{
    Console.WriteLine("  ⚠️ 无 token，跳过");
}
else
{
    try
    {
        var apiReq = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/admin/documents?page=1&pageSize=5");
        apiReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var sw = Stopwatch.StartNew();
        var apiResp = await client.SendAsync(apiReq);
        var apiBody = await apiResp.Content.ReadAsStringAsync();
        sw.Stop();

        Console.WriteLine($"  状态码: {(int)apiResp.StatusCode} {apiResp.StatusCode}");
        Console.WriteLine($"  耗时: {sw.ElapsedMilliseconds}ms");

        if (apiResp.IsSuccessStatusCode)
        {
            Console.WriteLine($"  ✅ API 调用成功");
            Console.WriteLine($"  响应: {apiBody[..Math.Min(200, apiBody.Length)]}");
        }
        else
        {
            Console.WriteLine($"  ❌ API 返回 {(int)apiResp.StatusCode}");
            Console.WriteLine($"  响应: {apiBody[..Math.Min(500, apiBody.Length)]}");
            ok = false;
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  ❌ API 异常: {ex.GetType().Name}: {ex.Message}");
        if (ex.InnerException != null)
            Console.WriteLine($"     Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
        ok = false;
    }
}

// ---------- 汇总 ----------
Console.WriteLine();
Console.WriteLine("=== 诊断汇总 ===");
if (ok)
{
    Console.WriteLine("✅ 所有检查通过");
}
else
{
    Console.WriteLine("❌ 存在问题，请检查上方输出");
    // 给出可能的原因
    Console.WriteLine();
    Console.WriteLine("可能的原因:");
    if (string.IsNullOrEmpty(accessToken))
        Console.WriteLine("  - 登录失败: 检查用户名密码、DocRetrieval 服务是否正常");
    else if (jwksKeys.Count == 0)
        Console.WriteLine("  - JWKS 为空: Identity 服务的密钥管理有问题");
    else
    {
        Console.WriteLine("  - JWT 验证失败，常见原因:");
        if (tokenKid != null && jwksKeys.All(k => k.Kid != tokenKid))
            Console.WriteLine($"    → Token kid={tokenKid} 在 JWKS 中找不到匹配密钥!");
        Console.WriteLine($"    → Token iss={tokenIss}, 期望 iss=QuantumZhou.Identity");
        Console.WriteLine($"    → Token aud={tokenAud}, 期望 aud=QuantumZhou.microservices");
        if (tokenExp > 0)
        {
            var expTime = DateTimeOffset.FromUnixTimeSeconds(tokenExp);
            if (expTime < DateTimeOffset.UtcNow)
                Console.WriteLine($"    → Token 已过期! ({expTime:yyyy-MM-dd HH:mm:ss} UTC)");
        }
    }
}

return ok ? 0 : 1;

static string Base64UrlDecode(string input)
{
    var output = input.Replace('-', '+').Replace('_', '/');
    switch (output.Length % 4)
    {
        case 2: output += "=="; break;
        case 3: output += "="; break;
    }
    return Encoding.UTF8.GetString(Convert.FromBase64String(output));
}
