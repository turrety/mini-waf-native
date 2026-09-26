// Protect a (pretend) server's requests with the universal adapter.
//
//     mvn -B -q compile
//     java --enable-native-access=ALL-UNNAMED -cp target/classes \
//         -Dmini_waf.library.path=../../target/release examples/Protect.java

import io.github.murylloex.miniwaf.CustomAdapter;
import io.github.murylloex.miniwaf.CustomAdapterHandlers;
import io.github.murylloex.miniwaf.FieldCondition;
import io.github.murylloex.miniwaf.HeaderMap;
import io.github.murylloex.miniwaf.MiniWaf;
import io.github.murylloex.miniwaf.MiniWafInstance;
import io.github.murylloex.miniwaf.ProtectionLevel;
import io.github.murylloex.miniwaf.RawBody;
import io.github.murylloex.miniwaf.WafAction;
import io.github.murylloex.miniwaf.WafConfig;
import io.github.murylloex.miniwaf.WafEvaluationResult;
import io.github.murylloex.miniwaf.WafField;
import io.github.murylloex.miniwaf.WafPresetName;
import io.github.murylloex.miniwaf.WafRule;
import java.util.List;

public class Protect {

    /** Your server's request type. */
    record Request(
        String method,
        String target,
        String peer,
        String userAgent
    ) {}

    /** Your server's response type. */
    static final class Response {

        int status = 200;
    }

    public static void main(String[] args) {
        // 1. Build the WAF once, at startup.
        MiniWafInstance waf = MiniWaf.createMiniWaf(
            new WafConfig()
                .presets(WafPresetName.DEFAULT)
                .level(ProtectionLevel.BALANCED)
                .rules(
                    new WafRule(
                        "allow-health",
                        new FieldCondition(WafField.PATH).equals("/health"),
                        WafAction.ALLOW
                    ).priority(1)
                )
        );

        // 2. Describe your server's request / response types once.
        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            new CustomAdapterHandlers<Request, Response>("example")
                .getMethod(Request::method)
                .getUrl(Request::target)
                .getIp(Request::peer)
                .getHeaders(req ->
                    new HeaderMap().insert("user-agent", req.userAgent())
                )
                .getRawBody(req -> new RawBody.Empty())
                .setResponseHeader((res, name, value) -> {})
                .drop((req, res, status, body) -> res.status = status)
        );

        // 3. Evaluate every request.
        List<Request> requests = List.of(
            new Request("GET", "/health", "198.51.100.4", "curl/8.0"),
            new Request(
                "GET",
                "/search?q=1'%20UNION%20SELECT%201",
                "198.51.100.4",
                "Mozilla/5.0"
            ),
            new Request("GET", "/", "198.51.100.4", "sqlmap/1.7")
        );
        for (Request request : requests) {
            Response response = new Response();
            WafEvaluationResult result = waf.protect(
                adapter,
                request,
                response
            );
            System.out.println(
                request.target() +
                    " -> " +
                    response.status +
                    " " +
                    result.matchedRule().map(WafRule::id).orElse("")
            );
        }
    }
}
