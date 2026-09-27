//! A dependency-free HTTP/1.1 server protected by mini-waf through the
//! universal adapter.
//!
//! ```sh
//! cargo run --example std_server
//! curl -i 'http://127.0.0.1:8080/search?q=hello'                       # 200
//! curl -i "http://127.0.0.1:8080/search?q=1'%20UNION%20SELECT%201"      # 403
//! curl -i -A sqlmap/1.7 http://127.0.0.1:8080/                          # 403
//! ```
//!
//! The HTTP parsing here is deliberately minimal; the point is the adapter.

use std::io::{
    BufRead,
    BufReader,
    Read,
    Write,
};
use std::net::{
    TcpListener,
    TcpStream,
};
use std::sync::Arc;

use mini_waf::{
    CustomAdapter,
    CustomAdapterHandlers,
    FieldCondition,
    HeaderMap,
    HeaderValue,
    MiniWafInstance,
    ProtectionLevel,
    RateLimitSpec,
    WafAction,
    WafCondition,
    WafConfig,
    WafDecision,
    WafField,
    WafPresetName,
    WafRule,
    create_adapter,
    create_mini_waf,
};

struct Request {
    method: String,
    target: String,
    peer: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn adapter() -> CustomAdapter<Request, Response> {
    create_adapter(
        CustomAdapterHandlers::new("std-server")
            .get_method(|req: &Request| req.method.clone())
            .get_url(|req: &Request| req.target.clone())
            .get_ip(|req: &Request| req.peer.clone())
            .get_headers(|req: &Request| {
                req.headers
                    .iter()
                    .map(|(name, value)| {
                        (name.to_lowercase(), HeaderValue::from(value.as_str()))
                    })
                    .collect::<HeaderMap>()
            })
            .get_raw_body(|req: &Request| req.body.clone())
            .set_response_header(|res: &mut Response, name, value| {
                res.headers.push((name.into(), value.into()))
            })
            .drop(|_req: &Request, res: &mut Response, status, body| {
                res.status = status;
                res.body = body.into();
            }),
    )
    .expect("every required handler is set")
}

fn read_request(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_owned();
    let target = parts.next().unwrap_or("/").to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(1 << 20);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let peer = stream
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    Ok(Request {
        method,
        target,
        peer,
        headers,
        body,
    })
}

fn handle(
    waf: &MiniWafInstance,
    adapter: &CustomAdapter<Request, Response>,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let request = read_request(&stream)?;
    let mut response = Response {
        status: 200,
        headers: Vec::new(),
        body: String::new(),
    };
    let result = waf.protect(adapter, &request, &mut response);
    if result.decision == WafDecision::Block {
        let rule = result.matched_rule.map(|rule| rule.id.as_str());
        eprintln!("blocked {} {} by {rule:?}", request.method, request.target);
    } else {
        response.body = format!("hello from {}\n", request.target);
    }
    let reason = if response.status == 200 {
        "OK"
    } else {
        "Forbidden"
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-length: {}\r\n",
        response.status,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    stream.write_all(format!("{head}\r\n{}", response.body).as_bytes())
}

fn main() -> std::io::Result<()> {
    let login_rate_limit = WafRule::new(
        "login-rate-limit",
        WafCondition::all([
            FieldCondition::new(WafField::Path).equals("/login").into(),
            FieldCondition::new(WafField::Ip)
                .rate_limit(RateLimitSpec::new(5, 60_000))
                .into(),
        ]),
        WafAction::Block,
    )
    .reason("Too many login attempts");
    let config = WafConfig::default()
        .presets([WafPresetName::Default])
        .level(ProtectionLevel::Balanced)
        .rules([login_rate_limit]);
    let waf = Arc::new(create_mini_waf(config, None));
    let adapter = Arc::new(adapter());
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!(
        "listening on http://127.0.0.1:8080 with {} rules",
        waf.rules().len()
    );
    for stream in listener.incoming() {
        let (waf, adapter) = (Arc::clone(&waf), Arc::clone(&adapter));
        std::thread::spawn(move || {
            if let Err(error) =
                stream.and_then(|stream| handle(&waf, &adapter, stream))
            {
                eprintln!("connection error: {error}");
            }
        });
    }
    Ok(())
}
