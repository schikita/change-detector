export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Проверка секретного ключа
    const key = url.searchParams.get("key");
    if (env.SECRET_KEY && key !== env.SECRET_KEY) {
      return new Response("Unauthorized", { status: 401 });
    }

    const targetUrl = url.searchParams.get("url");
    if (!targetUrl) {
      return new Response("Missing url parameter", { status: 400 });
    }

    let response;
    try {
      response = await fetch(targetUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "ru,en;q=0.8",
          "Cache-Control": "no-cache",
        },
        redirect: "follow",
      });
    } catch (err) {
      return new Response("Fetch error: " + err.message, { status: 502 });
    }

    const body = await response.text();

    return new Response(body, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") || "text/html; charset=utf-8",
        "X-Final-Url": response.url,
        "X-Status": String(response.status),
      },
    });
  },
};
