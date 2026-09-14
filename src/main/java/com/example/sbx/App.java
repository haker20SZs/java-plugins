package com.example.sbx;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class App {

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private static final Map<String, String> DOT_ENV = loadDotEnv();

    /*
     * ============================================================
     * Основные настройки
     * ============================================================
     */

    private static final String FILE_PATH =
            env("FILE_PATH", ".tmp");

    private static final String SHOW_LOG_RAW =
            env("SHOW_LOG", "true");

    private static final boolean SHOW_LOG =
            !List.of("false", "disable", "no")
                    .contains(SHOW_LOG_RAW.toLowerCase());


    /*
     * ============================================================
     * WireGuard / Cloudflare WARP
     * ============================================================
     *
     * Эти значения можно задать в .env:
     *
     * WG_PRIVATE_KEY=
     * WG_ADDRESS4=
     * WG_ADDRESS6=
     * WG_SERVER=
     * WG_PORT=
     * WG_PUBLIC_KEY=
     * WG_MTU=
     *
     * Значения ниже соответствуют прежнему конфигу.
     */

    private static final String WG_PRIVATE_KEY =
            env(
                    "WG_PRIVATE_KEY",
                    "YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY="
            );

    private static final String WG_ADDRESS4 =
            env(
                    "WG_ADDRESS4",
                    "172.16.0.2/32"
            );

    private static final String WG_ADDRESS6 =
            env(
                    "WG_ADDRESS6",
                    "2606:4700:110:8dfe:d141:69bb:6b80:925/128"
            );

    private static final String WG_SERVER =
            env(
                    "WG_SERVER",
                    "engage.cloudflareclient.com"
            );

    private static final int WG_PORT =
            envInt(
                    "WG_PORT",
                    2408
            );

    private static final String WG_PUBLIC_KEY =
            env(
                    "WG_PUBLIC_KEY",
                    "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            );

    private static final int WG_MTU =
            envInt(
                    "WG_MTU",
                    1280
            );


    /*
     * ============================================================
     * Пути
     * ============================================================
     */

    private static final Path ROOT =
            Path.of("").toAbsolutePath();

    private static final Path RUNTIME_DIR =
            ROOT.resolve(FILE_PATH).normalize();

    private static final Path SING_BOX_CONFIG_PATH =
            RUNTIME_DIR.resolve("config.json");

    private static final String ARCH =
            detectArch();


    /*
     * ============================================================
     * Main
     * ============================================================
     */

    public static void main(String[] args) throws Exception {
        startServer();
    }


    /*
     * ============================================================
     * Запуск
     * ============================================================
     */

    private static void startServer() throws Exception {

        Files.createDirectories(RUNTIME_DIR);

        cleanupOldFiles();

        log("========================================");
        log("Starting sing-box WireGuard mode");
        log("========================================");

        log("Architecture: " + ARCH);
        log("WireGuard server: " + WG_SERVER + ":" + WG_PORT);
        log("WireGuard MTU: " + WG_MTU);

        /*
         * Загружаем только sing-box.
         *
         * В старом коде здесь дополнительно загружались:
         * - cloudflared
         * - Nezha
         *
         * Здесь они полностью убраны.
         */

        String baseUrl =
                "https://" + ARCH + ".oooen.com";

        Path singBoxLib =
                downloadLibrary(
                        baseUrl + "/sbx.so",
                        "sbx.so"
                );


        /*
         * Генерируем только WireGuard-конфигурацию.
         */

        Map<String, Object> config =
                generateSingBoxConfig();

        Files.writeString(
                SING_BOX_CONFIG_PATH,
                toJson(config),
                StandardCharsets.UTF_8
        );

        log("sing-box config generated:");
        log(SING_BOX_CONFIG_PATH.toString());


        /*
         * Проверяем конфигурацию перед запуском.
         */

        log("Starting sing-box...");

        NativeService singBox =
                new NativeService(
                        "sing-box",
                        singBoxLib,
                        "StartSingBox",
                        "StopSingBox",
                        singboxPayload()
                );


        List<NativeService> services =
                new ArrayList<>();

        services.add(singBox);


        /*
         * Корректная остановка.
         */

        Runtime.getRuntime().addShutdownHook(
                new Thread(
                        () -> stopAll(services),
                        "shutdown-hook"
                )
        );


        /*
         * Запуск.
         */

        for (NativeService service : services) {
            service.start();
        }


        sleep(1000);

        log("========================================");
        log("sing-box is running");
        log("WireGuard outbound is active");
        log("All traffic -> WireGuard");
        log("========================================");


        /*
         * Оставляем процесс запущенным.
         */

        new CountDownLatch(1).await();
    }


    /*
     * ============================================================
     * Остановка сервисов
     * ============================================================
     */

    private static void stopAll(
            List<NativeService> services
    ) {

        log("");
        log("Stopping all services...");

        for (int i = services.size() - 1; i >= 0; i--) {

            try {
                services.get(i).stop();

            } catch (Exception ignored) {
            }
        }
    }


    /*
     * ============================================================
     * Native service
     * ============================================================
     */

    private static class NativeService {

        private final String name;
        private final Path libPath;
        private final String startSymbol;
        private final String stopSymbol;
        private final String payload;

        private NativeLibrary library;
        private Function stopFunction;
        private boolean running;


        NativeService(
                String name,
                Path libPath,
                String startSymbol,
                String stopSymbol,
                String payload
        ) {

            this.name = name;
            this.libPath = libPath;
            this.startSymbol = startSymbol;
            this.stopSymbol = stopSymbol;
            this.payload =
                    payload == null ? "" : payload;
        }


        void start() {

            library =
                    NativeLibrary.getInstance(
                            libPath.toString()
                    );

            Function startFunction =
                    library.getFunction(
                            startSymbol
                    );

            stopFunction =
                    library.getFunction(
                            stopSymbol
                    );


            Thread thread =
                    new Thread(
                            () -> {

                                try {

                                    int code =
                                            startFunction.invokeInt(
                                                    new Object[]{
                                                            payload
                                                    }
                                            );

                                    if (code != 0) {

                                        log(
                                                name
                                                        + " native service exited with code "
                                                        + code
                                        );
                                    }

                                } catch (Exception e) {

                                    log(
                                            name
                                                    + " native service failed: "
                                                    + e.getMessage()
                                    );
                                }

                            },
                            name + "-thread"
                    );


            thread.setDaemon(true);
            thread.start();

            running = true;
        }


        void stop() {

            if (!running || stopFunction == null) {
                return;
            }


            try {

                int code =
                        stopFunction.invokeInt(
                                new Object[]{}
                        );

                running = false;

                log(
                        name
                                + " stopped with code "
                                + code
                );

            } catch (Exception e) {

                log(
                        "Failed to stop "
                                + name
                                + ": "
                                + e.getMessage()
                );
            }
        }
    }


    /*
     * ============================================================
     * Скачать sing-box native library
     * ============================================================
     */

    private static Path downloadLibrary(
            String url,
            String fileName
    ) throws Exception {

        Path target =
                RUNTIME_DIR.resolve(fileName);


        if (Files.exists(target)) {

            log(
                    "Using cached native library: "
                            + target
            );

            return target;
        }


        Files.createDirectories(
                RUNTIME_DIR
        );


        Path tmp =
                RUNTIME_DIR.resolve(
                        fileName + ".download"
                );


        log(
                "Downloading "
                        + url
        );


        HttpRequest request =
                HttpRequest.newBuilder(
                                URI.create(url)
                        )
                        .timeout(
                                Duration.ofMinutes(3)
                        )
                        .GET()
                        .build();


        HttpResponse<byte[]> response =
                HTTP.send(
                        request,
                        HttpResponse.BodyHandlers.ofByteArray()
                );


        if (
                response.statusCode() < 200
                        ||
                response.statusCode() >= 300
        ) {

            throw new IOException(
                    "Failed to download "
                            + url
                            + ": HTTP "
                            + response.statusCode()
            );
        }


        Files.write(
                tmp,
                response.body()
        );


        Files.move(
                tmp,
                target,
                StandardCopyOption.REPLACE_EXISTING
        );


        target.toFile().setExecutable(
                true,
                false
        );


        return target;
    }


    /*
     * ============================================================
     * sing-box CONFIG
     * ============================================================
     *
     * Только WireGuard endpoint.
     *
     * НЕТ:
     *
     * VMess
     * VLESS
     * Reality
     * Hysteria2
     * TUIC
     * SOCKS5
     * AnyTLS
     * Argo
     * Nezha
     *
     * Весь трафик:
     *
     * application
     *      ↓
     * sing-box
     *      ↓
     * wireguard-out
     *      ↓
     * Cloudflare WARP
     *      ↓
     * Internet
     */

    private static Map<String, Object>
    generateSingBoxConfig() {


        /*
         * ========================================================
         * WireGuard endpoint
         * ========================================================
         */

        Map<String, Object> peer =
                mapOf(

                        "address",
                        WG_SERVER,

                        "port",
                        WG_PORT,

                        "public_key",
                        WG_PUBLIC_KEY,

                        /*
                         * Весь IPv4 и IPv6 трафик
                         * отправляется в WireGuard.
                         */

                        "allowed_ips",
                        listOf(
                                "0.0.0.0/0",
                                "::/0"
                        ),

                        /*
                         * Cloudflare WARP reserved bytes.
                         */

                        "reserved",
                        listOf(
                                78,
                                135,
                                76
                        )
                );


        Map<String, Object> wireguard =
                mapOf(

                        "type",
                        "wireguard",

                        "tag",
                        "wireguard-out",

                        "mtu",
                        WG_MTU,

                        /*
                         * Адреса интерфейса WireGuard.
                         */

                        "address",
                        listOf(
                                WG_ADDRESS4,
                                WG_ADDRESS6
                        ),

                        /*
                         * Приватный ключ клиента.
                         */

                        "private_key",
                        WG_PRIVATE_KEY,

                        /*
                         * Peer Cloudflare WARP.
                         */

                        "peers",
                        listOf(peer)
                );


        List<Object> endpoints =
                listOf(
                        wireguard
                );


        /*
         * ========================================================
         * Outbounds
         * ========================================================
         *
         * Для endpoint WireGuard отдельный direct outbound
         * не нужен.
         *
         * Endpoint wireguard-out используется непосредственно
         * в route.final.
         */

        List<Object> outbounds =
                new ArrayList<>();


        /*
         * ========================================================
         * Route
         * ========================================================
         *
         * Никаких правил доменов.
         *
         * Весь трафик -> wireguard-out.
         */

        Map<String, Object> route =
                mapOf(

                        "rules",
                        new ArrayList<>(),

                        "final",
                        "wireguard-out"
                );


        /*
         * ========================================================
         * Полный sing-box config
         * ========================================================
         */

        return mapOf(

                /*
                 * Логи выключены.
                 */

                "log",
                mapOf(
                        "disabled",
                        true,

                        "level",
                        "error",

                        "timestamp",
                        true
                ),


                /*
                 * Никаких inbound.
                 */

                "inbounds",
                new ArrayList<>(),


                /*
                 * Единственный endpoint.
                 */

                "endpoints",
                endpoints,


                /*
                 * Outbounds.
                 *
                 * Оставляем пустым, поскольку WireGuard
                 * используется как endpoint.
                 */

                "outbounds",
                outbounds,


                /*
                 * Routing.
                 */

                "route",
                route
        );
    }


    /*
     * ============================================================
     * Payload для sing-box
     * ============================================================
     */

    private static String singboxPayload() {

        return toJson(
                mapOf(
                        "config",
                        SING_BOX_CONFIG_PATH.toString(),

                        "workingDir",
                        ".",

                        "disableColor",
                        true
                )
        );
    }


    /*
     * ============================================================
     * Очистка старых файлов
     * ============================================================
     */

    private static void cleanupOldFiles() {

        List<String> files =
                List.of(
                        "boot.log",
                        "list.txt",
                        "config.json",
                        "config.yaml",
                        "cert.pem",
                        "private.key",
                        "tunnel.json",
                        "tunnel.yml",
                        "sub.txt"
                );


        for (String file : files) {

            try {

                Files.deleteIfExists(
                        RUNTIME_DIR.resolve(file)
                );

            } catch (IOException ignored) {
            }
        }


        deleteDirectory(
                ROOT.resolve(".tmp")
        );
    }


    /*
     * ============================================================
     * Удаление директории
     * ============================================================
     */

    private static void deleteDirectory(
            Path path
    ) {

        if (!Files.exists(path)) {
            return;
        }


        try (
                var stream =
                        Files.walk(path)
        ) {

            List<Path> paths =
                    stream
                            .sorted(
                                    (a, b) ->
                                            b.compareTo(a)
                            )
                            .collect(
                                    Collectors.toList()
                            );


            for (Path p : paths) {

                Files.deleteIfExists(p);
            }

        } catch (IOException ignored) {
        }
    }


    /*
     * ============================================================
     * HTTP GET
     * ============================================================
     */

    private static String getText(
            String url,
            Duration timeout
    ) throws Exception {

        HttpRequest request =
                HttpRequest.newBuilder(
                                URI.create(url)
                        )
                        .timeout(timeout)
                        .GET()
                        .build();


        HttpResponse<String> response =
                HTTP.send(
                        request,
                        HttpResponse.BodyHandlers.ofString(
                                StandardCharsets.UTF_8
                        )
                );


        if (
                response.statusCode() < 200
                        ||
                response.statusCode() >= 300
        ) {

            throw new IOException(
                    "HTTP "
                            + response.statusCode()
            );
        }


        return response.body();
    }


    /*
     * ============================================================
     * HTTP POST JSON
     * ============================================================
     */

    private static void postJson(
            String url,
            String json,
            Duration timeout
    ) throws Exception {

        HttpRequest request =
                HttpRequest.newBuilder(
                                URI.create(url)
                        )
                        .timeout(timeout)
                        .header(
                                "Content-Type",
                                "application/json"
                        )
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        json,
                                        StandardCharsets.UTF_8
                                )
                        )
                        .build();


        HTTP.send(
                request,
                HttpResponse.BodyHandlers.discarding()
        );
    }


    /*
     * ============================================================
     * Command
     * ============================================================
     */

    private static int runCommand(
            String... command
    ) throws IOException, InterruptedException {

        return new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
                .waitFor();
    }


    /*
     * ============================================================
     * JSON serializer
     * ============================================================
     */

    private static String toJson(
            Object value
    ) {

        if (value == null) {
            return "null";
        }


        if (value instanceof String) {

            return "\""
                    + escapeJson((String) value)
                    + "\"";
        }


        if (
                value instanceof Number
                        ||
                value instanceof Boolean
        ) {

            return value.toString();
        }


        if (value instanceof Map<?, ?>) {

            Map<?, ?> map =
                    (Map<?, ?>) value;


            return map.entrySet()
                    .stream()
                    .map(
                            e ->
                                    toJson(
                                            String.valueOf(
                                                    e.getKey()
                                            )
                                    )
                                            + ":"
                                            + toJson(
                                            e.getValue()
                                    )
                    )
                    .collect(
                            Collectors.joining(
                                    ",",
                                    "{",
                                    "}"
                            )
                    );
        }


        if (value instanceof Iterable<?>) {

            Iterable<?> iterable =
                    (Iterable<?>) value;


            List<String> items =
                    new ArrayList<>();


            for (Object item : iterable) {

                items.add(
                        toJson(item)
                );
            }


            return "["
                    + String.join(
                    ",",
                    items
            )
                    + "]";
        }


        return toJson(
                String.valueOf(value)
        );
    }


    /*
     * ============================================================
     * JSON escape
     * ============================================================
     */

    private static String escapeJson(
            String value
    ) {

        StringBuilder out =
                new StringBuilder();


        for (
                int i = 0;
                i < value.length();
                i++
        ) {

            char c =
                    value.charAt(i);


            switch (c) {

                case '\\':

                    out.append("\\\\");
                    break;


                case '"':

                    out.append("\\\"");
                    break;


                case '\n':

                    out.append("\\n");
                    break;


                case '\r':

                    out.append("\\r");
                    break;


                case '\t':

                    out.append("\\t");
                    break;


                default:

                    out.append(c);
            }
        }


        return out.toString();
    }


    /*
     * ============================================================
     * Map helper
     * ============================================================
     */

    private static Map<String, Object> mapOf(
            Object... values
    ) {

        Map<String, Object> map =
                new LinkedHashMap<>();


        for (
                int i = 0;
                i < values.length;
                i += 2
        ) {

            map.put(
                    String.valueOf(values[i]),
                    values[i + 1]
            );
        }


        return map;
    }


    /*
     * ============================================================
     * List helper
     * ============================================================
     */

    private static List<Object> listOf(
            Object... values
    ) {

        return new ArrayList<>(
                List.of(values)
        );
    }


    /*
     * ============================================================
     * Environment
     * ============================================================
     */

    private static String env(
            String name,
            String fallback
    ) {

        String value =
                DOT_ENV.get(name);


        if (value == null) {

            value =
                    System.getenv(name);
        }


        return value == null || value.isEmpty()
                ? fallback
                : value;
    }


    /*
     * ============================================================
     * Environment integer
     * ============================================================
     */

    private static int envInt(
            String name,
            int fallback
    ) {

        try {

            return Integer.parseInt(
                    env(
                            name,
                            String.valueOf(fallback)
                    )
            );

        } catch (Exception e) {

            return fallback;
        }
    }


    /*
     * ============================================================
     * Load .env
     * ============================================================
     */

    private static Map<String, String>
    loadDotEnv() {

        Map<String, String> values =
                new LinkedHashMap<>();


        Path envPath =
                Path.of(".env")
                        .toAbsolutePath()
                        .normalize();


        if (!Files.exists(envPath)) {

            return values;
        }


        try {

            for (
                    String line :
                    Files.readAllLines(
                            envPath,
                            StandardCharsets.UTF_8
                    )
            ) {

                parseDotEnvLine(line)
                        .ifPresent(
                                entry ->
                                        values.put(
                                                entry.getKey(),
                                                entry.getValue()
                                        )
                        );
            }

        } catch (IOException e) {

            log(
                    "Failed to read .env: "
                            + e.getMessage()
            );
        }


        return values;
    }


    /*
     * ============================================================
     * Parse .env line
     * ============================================================
     */

    private static Optional<Map.Entry<String, String>>
    parseDotEnvLine(
            String line
    ) {

        String trimmed =
                line.trim();


        if (
                trimmed.isEmpty()
                        ||
                trimmed.startsWith("#")
        ) {

            return Optional.empty();
        }


        if (
                trimmed.startsWith("export ")
        ) {

            trimmed =
                    trimmed
                            .substring(
                                    "export ".length()
                            )
                            .trim();
        }


        int equals =
                trimmed.indexOf('=');


        if (equals <= 0) {

            return Optional.empty();
        }


        String key =
                trimmed
                        .substring(0, equals)
                        .trim();


        if (key.isEmpty()) {

            return Optional.empty();
        }


        String value =
                trimmed
                        .substring(equals + 1)
                        .trim();


        return Optional.of(
                Map.entry(
                        key,
                        parseDotEnvValue(value)
                )
        );
    }


    /*
     * ============================================================
     * Parse .env value
     * ============================================================
     */

    private static String parseDotEnvValue(
            String value
    ) {

        if (value.length() >= 2) {

            char quote =
                    value.charAt(0);


            if (
                    (quote == '"' || quote == '\'')
                            &&
                    value.charAt(
                            value.length() - 1
                    ) == quote
            ) {

                value =
                        value.substring(
                                1,
                                value.length() - 1
                        );


                return quote == '"'
                        ? unescapeDotEnvValue(value)
                        : value;
            }
        }


        return stripInlineComment(
                value
        ).trim();
    }


    /*
     * ============================================================
     * Inline comments
     * ============================================================
     */

    private static String stripInlineComment(
            String value
    ) {

        for (
                int i = 0;
                i < value.length();
                i++
        ) {

            if (
                    value.charAt(i) == '#'
                            &&
                    (
                            i == 0
                                    ||
                            Character.isWhitespace(
                                    value.charAt(i - 1)
                            )
                    )
            ) {

                return value.substring(
                        0,
                        i
                );
            }
        }


        return value;
    }


    /*
     * ============================================================
     * Unescape .env
     * ============================================================
     */

    private static String unescapeDotEnvValue(
            String value
    ) {

        StringBuilder out =
                new StringBuilder();


        boolean escaped =
                false;


        for (
                int i = 0;
                i < value.length();
                i++
        ) {

            char c =
                    value.charAt(i);


            if (escaped) {

                switch (c) {

                    case 'n':
                        out.append('\n');
                        break;

                    case 'r':
                        out.append('\r');
                        break;

                    case 't':
                        out.append('\t');
                        break;

                    default:
                        out.append(c);
                        break;
                }


                escaped = false;

            } else if (c == '\\') {

                escaped = true;

            } else {

                out.append(c);
            }
        }


        if (escaped) {

            out.append('\\');
        }


        return out.toString();
    }


    /*
     * ============================================================
     * Architecture
     * ============================================================
     */

    private static String detectArch() {

        String arch =
                System.getProperty(
                        "os.arch",
                        ""
                ).toLowerCase();


        if (
                arch.contains("aarch64")
                        ||
                arch.contains("arm64")
        ) {

            return "arm64";
        }


        return "amd64";
    }


    /*
     * ============================================================
     * Log
     * ============================================================
     */

    private static void log(
            String message
    ) {

        if (SHOW_LOG) {

            System.out.println(
                    message
            );
        }
    }


    /*
     * ============================================================
     * Sleep
     * ============================================================
     */

    private static void sleep(
            long millis
    ) {

        try {

            Thread.sleep(millis);

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();
        }
    }
}
