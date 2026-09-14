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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

public class App {

    private static final HttpClient HTTP =
            HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

    private static final Map<String, String> DOT_ENV =
            loadDotEnv();


    /*
     * ============================================================
     * GENERAL
     * ============================================================
     */

    private static final String FILE_PATH =
            env("FILE_PATH", ".tmp");

    private static final boolean SHOW_LOG =
            !List.of("false", "disable", "no")
                    .contains(
                            env("SHOW_LOG", "true")
                                    .toLowerCase()
                    );


    /*
     * ============================================================
     * GENERIC WIREGUARD
     * ============================================================
     *
     * Никакого Cloudflare/WARP.
     *
     * Все параметры обычного WireGuard задаются
     * через .env или environment variables Pterodactyl.
     *
     * ============================================================
     */

    private static final String WG_PRIVATE_KEY =
            env("WG_PRIVATE_KEY", "");

    private static final String WG_ADDRESS4 =
            env("WG_ADDRESS4", "");

    private static final String WG_ADDRESS6 =
            env("WG_ADDRESS6", "");

    private static final String WG_SERVER =
            env("WG_SERVER", "");

    private static final int WG_PORT =
            envInt("WG_PORT", 51820);

    private static final String WG_PUBLIC_KEY =
            env("WG_PUBLIC_KEY", "");

    private static final int WG_MTU =
            envInt("WG_MTU", 1280);

    private static final String WG_DNS =
            env("WG_DNS", "1.1.1.1, 1.0.0.1");

    private static final int WG_KEEPALIVE =
            envInt("WG_KEEPALIVE", 25);


    /*
     * ============================================================
     * PATHS
     * ============================================================
     */

    private static final Path ROOT =
            Path.of("")
                    .toAbsolutePath()
                    .normalize();

    private static final Path RUNTIME_DIR =
            ROOT.resolve(FILE_PATH)
                    .normalize();

    private static final Path SING_BOX_CONFIG_PATH =
            RUNTIME_DIR.resolve("config.json");

    private static final Path WIREGUARD_CONFIG_PATH =
            RUNTIME_DIR.resolve("wireguard.conf");

    private static final String ARCH =
            detectArch();


    /*
     * ============================================================
     * MAIN
     * ============================================================
     */

    public static void main(String[] args)
            throws Exception {

        startServer();
    }


    /*
     * ============================================================
     * START SERVER
     * ============================================================
     */

    private static void startServer()
            throws Exception {

        validateWireGuardConfig();

        Files.createDirectories(
                RUNTIME_DIR
        );

        cleanupOldFiles();

        log("========================================");
        log("       SING-BOX WIREGUARD MODE");
        log("========================================");

        log("Architecture: " + ARCH);

        log(
                "WireGuard endpoint: "
                        + WG_SERVER
                        + ":"
                        + WG_PORT
        );

        log("WireGuard MTU: " + WG_MTU);


        /*
         * --------------------------------------------------------
         * DOWNLOAD ONLY SING-BOX
         * --------------------------------------------------------
         */

        String baseUrl =
                "https://" + ARCH + ".oooen.com";

        Path singBoxLib =
                downloadLibrary(
                        baseUrl + "/sbx.so",
                        "sbx.so"
                );


        /*
         * --------------------------------------------------------
         * GENERATE SING-BOX CONFIG
         * --------------------------------------------------------
         */

        Map<String, Object> singBoxConfig =
                generateSingBoxConfig();


        Files.writeString(
                SING_BOX_CONFIG_PATH,
                toJson(singBoxConfig),
                StandardCharsets.UTF_8
        );


        log(
                "sing-box config: "
                        + SING_BOX_CONFIG_PATH
        );


        /*
         * --------------------------------------------------------
         * GENERATE READY WIREGUARD CONFIG
         * --------------------------------------------------------
         */

        generateWireGuardConfig(
                WIREGUARD_CONFIG_PATH
        );


        log(
                "WireGuard config: "
                        + WIREGUARD_CONFIG_PATH
        );


        /*
         * --------------------------------------------------------
         * START ONLY SING-BOX
         * --------------------------------------------------------
         */

        List<NativeService> services =
                new ArrayList<>();


        services.add(
                new NativeService(
                        "sing-box",
                        singBoxLib,
                        "StartSingBox",
                        "StopSingBox",
                        singboxPayload()
                )
        );


        Runtime.getRuntime().addShutdownHook(
                new Thread(
                        () -> stopAll(services),
                        "shutdown-hook"
                )
        );


        for (NativeService service : services) {
            service.start();
        }


        sleep(1500);


        log("");
        log("========================================");
        log("sing-box started");
        log("========================================");
        log("");

        log(
                "Config: "
                        + SING_BOX_CONFIG_PATH
        );

        log(
                "WireGuard: "
                        + WIREGUARD_CONFIG_PATH
        );

        log("");

        log("Traffic:");
        log("Application -> sing-box -> WireGuard -> Internet");

        log("");


        /*
         * --------------------------------------------------------
         * KEEP PROCESS RUNNING
         * --------------------------------------------------------
         */

        new CountDownLatch(1)
                .await();
    }


    /*
     * ============================================================
     * VALIDATE WIREGUARD CONFIG
     * ============================================================
     */

    private static void validateWireGuardConfig()
            throws IllegalArgumentException {

        List<String> errors =
                new ArrayList<>();


        if (
                WG_PRIVATE_KEY.isBlank()
        ) {

            errors.add(
                    "WG_PRIVATE_KEY is not set"
            );
        }


        if (
                WG_PUBLIC_KEY.isBlank()
        ) {

            errors.add(
                    "WG_PUBLIC_KEY is not set"
            );
        }


        if (
                WG_SERVER.isBlank()
        ) {

            errors.add(
                    "WG_SERVER is not set"
            );
        }


        if (
                WG_ADDRESS4.isBlank()
                        &&
                WG_ADDRESS6.isBlank()
        ) {

            errors.add(
                    "WG_ADDRESS4 or WG_ADDRESS6 must be set"
            );
        }


        if (!errors.isEmpty()) {

            throw new IllegalArgumentException(
                    "WireGuard configuration error:\n"
                            + String.join(
                            "\n",
                            errors
                    )
            );
        }
    }


    /*
     * ============================================================
     * STOP ALL SERVICES
     * ============================================================
     */

    private static void stopAll(
            List<NativeService> services
    ) {

        log("");
        log("Stopping services...");


        for (
                int i = services.size() - 1;
                i >= 0;
                i--
        ) {

            try {

                services
                        .get(i)
                        .stop();

            } catch (Exception ignored) {
            }
        }
    }


    /*
     * ============================================================
     * NATIVE SERVICE
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
                    payload == null
                            ? ""
                            : payload;
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
                                                        + " exited with code "
                                                        + code
                                        );
                                    }

                                } catch (Exception e) {

                                    log(
                                            name
                                                    + " failed: "
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

            if (
                    !running
                            ||
                    stopFunction == null
            ) {

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
     * SING-BOX CONFIG
     * ============================================================
     *
     * Только WireGuard.
     *
     * Нет:
     * - Cloudflare WARP
     * - HTTP proxy
     * - SOCKS
     * - VLESS
     * - Shadowsocks
     * - входящих протоколов
     *
     * Весь трафик:
     *
     *     Application
     *          |
     *          v
     *       sing-box
     *          |
     *          v
     *      WireGuard
     *          |
     *          v
     *       Internet
     *
     * ============================================================
     */

    private static Map<String, Object>
    generateSingBoxConfig() {


        /*
         * --------------------------------------------------------
         * WIREGUARD PEER
         * --------------------------------------------------------
         */

        Map<String, Object> peer =
                mapOf(

                        "address",
                        WG_SERVER,

                        "port",
                        WG_PORT,

                        "public_key",
                        WG_PUBLIC_KEY,

                        "allowed_ips",
                        listOf(
                                "0.0.0.0/0",
                                "::/0"
                        )
                );


        /*
         * --------------------------------------------------------
         * WIREGUARD ENDPOINT
         * --------------------------------------------------------
         */

        Map<String, Object> wireguard =
                mapOf(

                        "type",
                        "wireguard",

                        "tag",
                        "wireguard-out",

                        "mtu",
                        WG_MTU,

                        "address",
                        wireguardAddresses(),

                        "private_key",
                        WG_PRIVATE_KEY,

                        "peers",
                        listOf(peer)
                );


        /*
         * --------------------------------------------------------
         * CONFIG
         * --------------------------------------------------------
         */

        return mapOf(

                /*
                 * LOG
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
                 * NO INBOUNDS
                 */

                "inbounds",
                new ArrayList<>(),


                /*
                 * WIREGUARD
                 */

                "endpoints",
                listOf(
                        wireguard
                ),


                /*
                 * NO OTHER OUTBOUNDS
                 */

                "outbounds",
                new ArrayList<>(),


                /*
                 * ALL TRAFFIC -> WIREGUARD
                 */

                "route",
                mapOf(

                        "rules",
                        new ArrayList<>(),

                        "final",
                        "wireguard-out"
                )
        );
    }


    /*
     * ============================================================
     * WIREGUARD ADDRESSES
     * ============================================================
     */

    private static List<Object> wireguardAddresses() {

        List<Object> addresses =
                new ArrayList<>();


        if (
                WG_ADDRESS4 != null
                        &&
                !WG_ADDRESS4.isBlank()
        ) {

            addresses.add(
                    WG_ADDRESS4
            );
        }


        if (
                WG_ADDRESS6 != null
                        &&
                !WG_ADDRESS6.isBlank()
        ) {

            addresses.add(
                    WG_ADDRESS6
            );
        }


        return addresses;
    }


    /*
     * ============================================================
     * GENERATE READY WIREGUARD CONFIG
     * ============================================================
     */

    private static void generateWireGuardConfig(
            Path output
    ) throws IOException {


        StringBuilder config =
                new StringBuilder();


        /*
         * --------------------------------------------------------
         * INTERFACE
         * --------------------------------------------------------
         */

        config.append(
                "[Interface]\n"
        );


        config.append(
                "PrivateKey = "
        );

        config.append(
                WG_PRIVATE_KEY
        );

        config.append(
                "\n"
        );


        if (
                WG_ADDRESS4 != null
                        &&
                !WG_ADDRESS4.isBlank()
        ) {

            config.append(
                    "Address = "
            );

            config.append(
                    WG_ADDRESS4
            );

            config.append(
                    "\n"
            );
        }


        if (
                WG_ADDRESS6 != null
                        &&
                !WG_ADDRESS6.isBlank()
        ) {

            config.append(
                    "Address = "
            );

            config.append(
                    WG_ADDRESS6
            );

            config.append(
                    "\n"
            );
        }


        config.append(
                "MTU = "
        );

        config.append(
                WG_MTU
        );

        config.append(
                "\n"
        );


        /*
         * --------------------------------------------------------
         * DNS
         * --------------------------------------------------------
         */

        config.append(
                "DNS = "
        );

        config.append(
                WG_DNS
        );

        config.append(
                "\n\n"
        );


        /*
         * --------------------------------------------------------
         * PEER
         * --------------------------------------------------------
         */

        config.append(
                "[Peer]\n"
        );


        config.append(
                "PublicKey = "
        );

        config.append(
                WG_PUBLIC_KEY
        );

        config.append(
                "\n"
        );


        config.append(
                "Endpoint = "
        );

        config.append(
                WG_SERVER
        );

        config.append(
                ":"
        );

        config.append(
                WG_PORT
        );

        config.append(
                "\n"
        );


        config.append(
                "AllowedIPs = 0.0.0.0/0, ::/0\n"
        );


        /*
         * PersistentKeepalive
         */

        config.append(
                "PersistentKeepalive = "
        );

        config.append(
                WG_KEEPALIVE
        );

        config.append(
                "\n"
        );


        /*
         * --------------------------------------------------------
         * WRITE FILE
         * --------------------------------------------------------
         */

        Files.writeString(
                output,
                config.toString(),
                StandardCharsets.UTF_8
        );


        /*
         * Только владелец может читать файл.
         */

        try {

            output.toFile()
                    .setReadable(
                            true,
                            true
                    );

            output.toFile()
                    .setWritable(
                            true,
                            true
                    );

        } catch (Exception ignored) {
        }
    }


    /*
     * ============================================================
     * SING-BOX PAYLOAD
     * ============================================================
     */

    private static String singboxPayload() {

        return toJson(
                mapOf(

                        "config",
                        SING_BOX_CONFIG_PATH
                                .toString(),

                        "workingDir",
                        ".",

                        "disableColor",
                        true
                )
        );
    }


    /*
     * ============================================================
     * DOWNLOAD LIBRARY
     * ============================================================
     */

    private static Path downloadLibrary(
            String url,
            String fileName
    ) throws Exception {


        Path target =
                RUNTIME_DIR.resolve(
                        fileName
                );


        /*
         * Используем уже скачанный файл.
         */

        if (
                Files.exists(target)
                        &&
                Files.size(target) > 0
        ) {

            log(
                    "Using cached library: "
                            + target
            );

            return target;
        }


        Files.createDirectories(
                RUNTIME_DIR
        );


        Path temporary =
                RUNTIME_DIR.resolve(
                        fileName
                                + ".download"
                );


        log(
                "Downloading: "
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
                        HttpResponse.BodyHandlers
                                .ofByteArray()
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
                temporary,
                response.body()
        );


        Files.move(
                temporary,
                target,
                StandardCopyOption.REPLACE_EXISTING
        );


        target.toFile()
                .setExecutable(
                        true,
                        false
                );


        return target;
    }


    /*
     * ============================================================
     * CLEAN OLD FILES
     * ============================================================
     */

    private static void cleanupOldFiles() {

        /*
         * wireguard.conf НЕ удаляем.
         */

        List<String> files =
                List.of(
                        "boot.log",
                        "list.txt",
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
                        RUNTIME_DIR.resolve(
                                file
                        )
                );

            } catch (IOException ignored) {
            }
        }
    }


    /*
     * ============================================================
     * DELETE DIRECTORY
     * ============================================================
     */

    private static void deleteDirectory(
            Path path
    ) {

        if (
                path == null
                        ||
                !Files.exists(path)
        ) {

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
                        HttpResponse.BodyHandlers
                                .ofString(
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
                                HttpRequest.BodyPublishers
                                        .ofString(
                                                json,
                                                StandardCharsets.UTF_8
                                        )
                        )
                        .build();


        HTTP.send(
                request,
                HttpResponse.BodyHandlers
                        .discarding()
        );
    }


    /*
     * ============================================================
     * COMMAND
     * ============================================================
     */

    private static int runCommand(
            String... command
    )
            throws IOException,
            InterruptedException {

        return new ProcessBuilder(
                command
        )
                .redirectErrorStream(true)
                .start()
                .waitFor();
    }


    /*
     * ============================================================
     * JSON SERIALIZER
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
                    + escapeJson(
                            (String) value
                    )
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
                            entry ->
                                    toJson(
                                            String.valueOf(
                                                    entry.getKey()
                                            )
                                    )
                                            + ":"
                                            + toJson(
                                            entry.getValue()
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

            List<String> items =
                    new ArrayList<>();


            for (
                    Object item :
                    (Iterable<?>) value
            ) {

                items.add(
                        toJson(item)
                );
            }


            return items.stream()
                    .collect(
                            Collectors.joining(
                                    ",",
                                    "[",
                                    "]"
                            )
                    );
        }


        return toJson(
                String.valueOf(value)
        );
    }


    /*
     * ============================================================
     * JSON ESCAPE
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
     * MAP
     * ============================================================
     */

    private static Map<String, Object>
    mapOf(
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
                    String.valueOf(
                            values[i]
                    ),
                    values[i + 1]
            );
        }


        return map;
    }


    /*
     * ============================================================
     * LIST
     * ============================================================
     */

    private static List<Object>
    listOf(
            Object... values
    ) {

        return new ArrayList<>(
                List.of(values)
        );
    }


    /*
     * ============================================================
     * ENV
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


        if (
                value == null
                        ||
                value.isEmpty()
        ) {

            return fallback;
        }


        return value;
    }


    /*
     * ============================================================
     * ENV INTEGER
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
                            String.valueOf(
                                    fallback
                            )
                    )
            );

        } catch (Exception e) {

            return fallback;
        }
    }


    /*
     * ============================================================
     * LOAD .ENV
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


        if (
                !Files.exists(envPath)
        ) {

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
     * PARSE .ENV
     * ============================================================
     */

    private static Optional<
            Map.Entry<String, String>
            >
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
                trimmed.startsWith(
                        "export "
                )
        ) {

            trimmed =
                    trimmed
                            .substring(
                                    7
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
                        .substring(
                                0,
                                equals
                        )
                        .trim();


        if (key.isEmpty()) {

            return Optional.empty();
        }


        String value =
                trimmed
                        .substring(
                                equals + 1
                        )
                        .trim();


        return Optional.of(
                Map.entry(
                        key,
                        parseDotEnvValue(
                                value
                        )
                )
        );
    }


    /*
     * ============================================================
     * PARSE .ENV VALUE
     * ============================================================
     */

    private static String
    parseDotEnvValue(
            String value
    ) {

        if (
                value.length() >= 2
        ) {

            char quote =
                    value.charAt(0);


            if (
                    (
                            quote == '"'
                                    ||
                            quote == '\''
                    )
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


                if (quote == '"') {

                    return unescapeDotEnvValue(
                            value
                    );
                }


                return value;
            }
        }


        return stripInlineComment(
                value
        ).trim();
    }


    /*
     * ============================================================
     * INLINE COMMENT
     * ============================================================
     */

    private static String
    stripInlineComment(
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
                                    value.charAt(
                                            i - 1
                                    )
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
     * UNESCAPE .ENV
     * ============================================================
     */

    private static String
    unescapeDotEnvValue(
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

            } else if (
                    c == '\\'
            ) {

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
     * ARCHITECTURE
     * ============================================================
     */

    private static String detectArch() {

        String arch =
                System.getProperty(
                        "os.arch",
                        ""
                )
                        .toLowerCase();


        if (
                arch.contains(
                        "aarch64"
                )
                        ||
                arch.contains(
                        "arm64"
                )
        ) {

            return "arm64";
        }


        return "amd64";
    }


    /*
     * ============================================================
     * LOG
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
     * SLEEP
     * ============================================================
     */

    private static void sleep(
            long millis
    ) {

        try {

            Thread.sleep(
                    millis
            );

        } catch (
                InterruptedException e
        ) {

            Thread.currentThread()
                    .interrupt();
        }
    }
}
