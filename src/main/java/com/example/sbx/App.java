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
     * WIREGUARD
     *
     * ВЕСЬ конфиг WireGuard берётся только из:
     *
     *     WG_CONFIG
     *
     * Больше никаких:
     *
     *     WG_PRIVATE_KEY
     *     WG_PUBLIC_KEY
     *     WG_SERVER
     *     WG_PORT
     *     WG_ADDRESS4
     *     WG_ADDRESS6
     *     WG_MTU
     *     WG_DNS
     *     WG_KEEPALIVE
     *
     * не используется.
     * ============================================================
     */

    private static final String WG_CONFIG =
            loadWireGuardConfig();


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

        Files.createDirectories(
                RUNTIME_DIR
        );

        cleanupOldFiles();

        /*
         * --------------------------------------------------------
         * PARSE WIREGUARD
         * --------------------------------------------------------
         */

        WireGuardConfig wireGuard =
                parseWireGuardConfig(
                        WG_CONFIG
                );

        validateWireGuardConfig(
                wireGuard
        );

        log("========================================");
        log("       SING-BOX WIREGUARD MODE");
        log("========================================");

        log("Architecture: " + ARCH);

        log(
                "WireGuard endpoint: "
                        + wireGuard.endpointAddress()
        );

        log(
                "WireGuard MTU: "
                        + (
                        wireGuard.mtu != null
                                ? wireGuard.mtu
                                : "default"
                )
        );


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
                generateSingBoxConfig(
                        wireGuard
                );

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
         * SAVE ORIGINAL WIREGUARD CONFIG
         * --------------------------------------------------------
         *
         * WG_CONFIG записывается без пересборки.
         *
         * То есть:
         *
         * Pterodactyl WG_CONFIG
         *          |
         *          v
         * .tmp/wireguard.conf
         *
         * --------------------------------------------------------
         */

        Files.writeString(
                WIREGUARD_CONFIG_PATH,
                WG_CONFIG.endsWith("\n")
                        ? WG_CONFIG
                        : WG_CONFIG + "\n",
                StandardCharsets.UTF_8
        );

        secureFile(
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


        /*
         * --------------------------------------------------------
         * SHUTDOWN HOOK
         * --------------------------------------------------------
         */

        Runtime.getRuntime().addShutdownHook(
                new Thread(
                        () -> stopAll(services),
                        "shutdown-hook"
                )
        );


        /*
         * --------------------------------------------------------
         * START SERVICES
         * --------------------------------------------------------
         */

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
        log(
                "Application -> sing-box -> WireGuard -> Internet"
        );

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
     * WIREGUARD CONFIG CLASS
     * ============================================================
     */

    private static class WireGuardConfig {

        private String privateKey;

        private final List<String> addresses =
                new ArrayList<>();

        private String mtu;

        private final List<String> dns =
                new ArrayList<>();

        private final List<WireGuardPeer> peers =
                new ArrayList<>();


        String primaryAddress() {

            if (addresses.isEmpty()) {
                return null;
            }

            return addresses.get(0);
        }


        String endpointAddress() {

            if (peers.isEmpty()) {
                return "unknown";
            }

            return peers.get(0).endpoint();
        }
    }


    /*
     * ============================================================
     * WIREGUARD PEER
     * ============================================================
     */

    private static class WireGuardPeer {

        private String publicKey;

        private String presharedKey;

        private String endpoint;

        private String address;

        private String port;

        private final List<String> allowedIps =
                new ArrayList<>();

        private String persistentKeepalive;


        String endpoint() {

            if (
                    address == null
                            ||
                    address.isBlank()
            ) {
                return endpoint != null
                        ? endpoint
                        : "unknown";
            }

            if (
                    port == null
                            ||
                    port.isBlank()
            ) {
                return address;
            }

            return address + ":" + port;
        }
    }


    /*
     * ============================================================
     * PARSE WIREGUARD CONFIG
     * ============================================================
     */

    private static WireGuardConfig parseWireGuardConfig(
            String raw
    ) {

        WireGuardConfig result =
                new WireGuardConfig();


        String config =
                raw
                        .replace("\r\n", "\n")
                        .replace('\r', '\n');


        String section = "";

        WireGuardPeer currentPeer = null;


        for (
                String rawLine :
                config.split("\n", -1)
        ) {

            String line =
                    rawLine.trim();


            /*
             * Empty line
             */

            if (line.isEmpty()) {
                continue;
            }


            /*
             * Comment
             */

            if (
                    line.startsWith("#")
                            ||
                    line.startsWith(";")
            ) {
                continue;
            }


            /*
             * Section
             */

            if (
                    line.startsWith("[")
                            &&
                    line.endsWith("]")
            ) {

                section =
                        line.substring(
                                1,
                                line.length() - 1
                        )
                                .trim()
                                .toLowerCase();


                if (
                        section.equals("peer")
                ) {

                    currentPeer =
                            new WireGuardPeer();

                    result.peers.add(
                            currentPeer
                    );
                }

                continue;
            }


            int equals =
                    line.indexOf('=');


            if (equals <= 0) {
                continue;
            }


            String key =
                    line.substring(
                            0,
                            equals
                    )
                            .trim()
                            .toLowerCase();


            String value =
                    line.substring(
                            equals + 1
                    )
                            .trim();


            /*
             * Remove inline comments only when
             * separated by whitespace.
             */

            value =
                    stripInlineComment(
                            value
                    )
                            .trim();


            /*
             * ----------------------------------------------------
             * INTERFACE
             * ----------------------------------------------------
             */

            if (
                    section.equals("interface")
            ) {

                switch (key) {

                    case "privatekey":

                        result.privateKey =
                                value;

                        break;


                    case "address":

                        for (
                                String address :
                                value.split(",")
                        ) {

                            String v =
                                    address.trim();

                            if (!v.isEmpty()) {
                                result.addresses.add(v);
                            }
                        }

                        break;


                    case "mtu":

                        result.mtu =
                                value;

                        break;


                    case "dns":

                        for (
                                String dns :
                                value.split(",")
                        ) {

                            String v =
                                    dns.trim();

                            if (!v.isEmpty()) {
                                result.dns.add(v);
                            }
                        }

                        break;

                    default:
                        break;
                }

                continue;
            }


            /*
             * ----------------------------------------------------
             * PEER
             * ----------------------------------------------------
             */

            if (
                    section.equals("peer")
                            &&
                    currentPeer != null
            ) {

                switch (key) {

                    case "publickey":

                        currentPeer.publicKey =
                                value;

                        break;


                    case "presharedkey":

                        currentPeer.presharedKey =
                                value;

                        break;


                    case "endpoint":

                        currentPeer.endpoint =
                                value;

                        parseEndpoint(
                                currentPeer
                        );

                        break;


                    case "allowedips":

                        for (
                                String ip :
                                value.split(",")
                        ) {

                            String v =
                                    ip.trim();

                            if (!v.isEmpty()) {
                                currentPeer.allowedIps.add(v);
                            }
                        }

                        break;


                    case "persistentkeepalive":

                        currentPeer.persistentKeepalive =
                                value;

                        break;

                    default:
                        break;
                }
            }
        }


        return result;
    }


    /*
     * ============================================================
     * PARSE ENDPOINT
     * ============================================================
     */

    private static void parseEndpoint(
            WireGuardPeer peer
    ) {

        if (
                peer.endpoint == null
                        ||
                peer.endpoint.isBlank()
        ) {
            return;
        }


        String endpoint =
                peer.endpoint.trim();


        /*
         * IPv6:
         *
         * [2001:db8::1]:51820
         */

        if (
                endpoint.startsWith("[")
        ) {

            int closing =
                    endpoint.indexOf(']');


            if (closing > 0) {

                peer.address =
                        endpoint.substring(
                                1,
                                closing
                        );


                if (
                        endpoint.length()
                                > closing + 1
                        &&
                        endpoint.charAt(
                                closing + 1
                        ) == ':'
                ) {

                    peer.port =
                            endpoint.substring(
                                    closing + 2
                            );
                }

                return;
            }
        }


        /*
         * Normal IPv4/domain:
         *
         * example.com:51820
         */

        int lastColon =
                endpoint.lastIndexOf(':');


        if (
                lastColon > 0
                        &&
                endpoint.indexOf(':')
                        == lastColon
        ) {

            peer.address =
                    endpoint.substring(
                            0,
                            lastColon
                    );

            peer.port =
                    endpoint.substring(
                            lastColon + 1
                    );

            return;
        }


        /*
         * Raw address without port
         */

        peer.address =
                endpoint;
    }


    /*
     * ============================================================
     * VALIDATE WIREGUARD CONFIG
     * ============================================================
     */

    private static void validateWireGuardConfig(
            WireGuardConfig config
    ) {

        List<String> errors =
                new ArrayList<>();


        if (
                config.privateKey == null
                        ||
                config.privateKey.isBlank()
        ) {

            errors.add(
                    "PrivateKey is missing in [Interface]"
            );
        }


        if (config.addresses.isEmpty()) {

            errors.add(
                    "Address is missing in [Interface]"
            );
        }


        if (config.peers.isEmpty()) {

            errors.add(
                    "[Peer] section is missing"
            );
        }


        for (
                int i = 0;
                i < config.peers.size();
                i++
        ) {

            WireGuardPeer peer =
                    config.peers.get(i);


            if (
                    peer.publicKey == null
                            ||
                    peer.publicKey.isBlank()
            ) {

                errors.add(
                        "PublicKey is missing in [Peer #"
                                + (i + 1)
                                + "]"
                );
            }


            if (
                    (
                            peer.endpoint == null
                                    ||
                            peer.endpoint.isBlank()
                    )
                            &&
                    (
                            peer.address == null
                                    ||
                            peer.address.isBlank()
                    )
            ) {

                errors.add(
                        "Endpoint is missing in [Peer #"
                                + (i + 1)
                                + "]"
                );
            }


            if (
                    peer.allowedIps.isEmpty()
            ) {

                errors.add(
                        "AllowedIPs is missing in [Peer #"
                                + (i + 1)
                                + "]"
                );
            }
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
     * GENERATE SING-BOX CONFIG
     * ============================================================
     */

    private static Map<String, Object>
    generateSingBoxConfig(
            WireGuardConfig config
    ) {


        /*
         * --------------------------------------------------------
         * PEERS
         * --------------------------------------------------------
         */

        List<Object> peers =
                new ArrayList<>();


        for (
                WireGuardPeer source :
                config.peers
        ) {

            Map<String, Object> peer =
                    new LinkedHashMap<>();


            /*
             * Address / port
             */

            String address =
                    source.address;

            String port =
                    source.port;


            /*
             * Если Endpoint не удалось разобрать,
             * пытаемся использовать его напрямую.
             */

            if (
                    (
                            address == null
                                    ||
                            address.isBlank()
                    )
                            &&
                    source.endpoint != null
            ) {

                parseEndpoint(source);

                address =
                        source.address;

                port =
                        source.port;
            }


            if (
                    address != null
                            &&
                    !address.isBlank()
            ) {

                peer.put(
                        "address",
                        address
                );
            }


            if (
                    port != null
                            &&
                    !port.isBlank()
            ) {

                try {

                    peer.put(
                            "port",
                            Integer.parseInt(
                                    port
                            )
                    );

                } catch (NumberFormatException e) {

                    throw new IllegalArgumentException(
                            "Invalid WireGuard endpoint port: "
                                    + port
                    );
                }
            }


            /*
             * Public key
             */

            peer.put(
                    "public_key",
                    source.publicKey
            );


            /*
             * Allowed IPs
             */

            peer.put(
                    "allowed_ips",
                    new ArrayList<>(
                            source.allowedIps
                    )
            );


            /*
             * PersistentKeepalive
             *
             * Поддерживаем стандартный параметр,
             * если он присутствует.
             */

            if (
                    source.persistentKeepalive != null
                            &&
                    !source.persistentKeepalive.isBlank()
            ) {

                try {

                    peer.put(
                            "persistent_keepalive_interval",
                            Integer.parseInt(
                                    source.persistentKeepalive
                            )
                    );

                } catch (
                        NumberFormatException ignored
                ) {
                }
            }


            /*
             * PresharedKey
             *
             * Передаём только если он указан.
             */

            if (
                    source.presharedKey != null
                            &&
                    !source.presharedKey.isBlank()
            ) {

                peer.put(
                        "pre_shared_key",
                        source.presharedKey
                );
            }


            peers.add(peer);
        }


        /*
         * --------------------------------------------------------
         * WIREGUARD ENDPOINT
         * --------------------------------------------------------
         */

        Map<String, Object> wireguard =
                new LinkedHashMap<>();


        wireguard.put(
                "type",
                "wireguard"
        );


        wireguard.put(
                "tag",
                "wireguard-out"
        );


        /*
         * MTU
         */

        if (
                config.mtu != null
                        &&
                !config.mtu.isBlank()
        ) {

            try {

                wireguard.put(
                        "mtu",
                        Integer.parseInt(
                                config.mtu
                        )
                );

            } catch (
                    NumberFormatException e
            ) {

                throw new IllegalArgumentException(
                        "Invalid WireGuard MTU: "
                                + config.mtu
                );
            }
        }


        /*
         * Addresses
         */

        wireguard.put(
                "address",
                new ArrayList<>(
                        config.addresses
                )
        );


        /*
         * Private key
         */

        wireguard.put(
                "private_key",
                config.privateKey
        );


        /*
         * Peers
         */

        wireguard.put(
                "peers",
                peers
        );


        /*
         * --------------------------------------------------------
         * CONFIG
         * --------------------------------------------------------
         */

        Map<String, Object> result =
                new LinkedHashMap<>();


        /*
         * LOG
         */

        result.put(
                "log",
                mapOf(
                        "disabled",
                        true,

                        "level",
                        "error",

                        "timestamp",
                        true
                )
        );


        /*
         * NO INBOUNDS
         */

        result.put(
                "inbounds",
                new ArrayList<>()
        );


        /*
         * WIREGUARD
         */

        result.put(
                "endpoints",
                listOf(
                        wireguard
                )
        );


        /*
         * NO OTHER OUTBOUNDS
         */

        result.put(
                "outbounds",
                new ArrayList<>()
        );


        /*
         * ALL TRAFFIC -> WIREGUARD
         */

        result.put(
                "route",
                mapOf(
                        "rules",
                        new ArrayList<>(),

                        "final",
                        "wireguard-out"
                )
        );


        return result;
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
         * wireguard.conf НЕ удаляем,
         * потому что он будет пересоздан из WG_CONFIG.
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
     * SECURE FILE
     * ============================================================
     */

    private static void secureFile(
            Path file
    ) {

        try {

            file.toFile()
                    .setReadable(
                            true,
                            true
                    );

            file.toFile()
                    .setWritable(
                            true,
                            true
                    );

        } catch (Exception ignored) {
        }
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
     * LOAD WIREGUARD CONFIG
     * ============================================================
     */

    private static String loadWireGuardConfig() {

        String value =
                DOT_ENV.get("WG_CONFIG");


        if (
                value == null
                        ||
                value.isBlank()
        ) {

            value =
                    System.getenv(
                            "WG_CONFIG"
                    );
        }


        if (
                value == null
                        ||
                value.isBlank()
        ) {

            throw new IllegalArgumentException(
                    "WireGuard configuration error:\n"
                            + "WG_CONFIG is not set"
            );
        }


        /*
         * Pterodactyl может передать \n
         * буквально двумя символами:
         *
         *     \n
         *
         * Преобразуем их в реальные переносы строк.
         */

        value =
                value.replace(
                        "\\r\\n",
                        "\n"
                );

        value =
                value.replace(
                        "\\n",
                        "\n"
                );

        value =
                value.replace(
                        "\\r",
                        "\n"
                );


        return value.trim() + "\n";
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
                trimmed.substring(
                        0,
                        equals
                )
                        .trim();


        if (key.isEmpty()) {
            return Optional.empty();
        }


        String value =
                trimmed.substring(
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

                    case '\\':
                        out.append('\\');
                        break;

                    case '"':
                        out.append('"');
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
