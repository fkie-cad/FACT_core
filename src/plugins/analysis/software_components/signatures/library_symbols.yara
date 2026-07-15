rule lwip {
    meta:
        software_name = "lwIP"
        open_source = true
        website = "https://savannah.nongnu.org/projects/lwip/"
        description = "Lightweight TCP/IP stack for embedded systems"
    strings:
        $a = /\x00lwip_\w+\x00/
        $b = /\x00(tcp|udp|pbuf|netif|etharp)_\w+\x00/
    condition:
        #a > 3 or (#a > 1 and #b > 3)
}

rule littlefs {
    meta:
        software_name = "littlefs"
        open_source = true
        website = "https://github.com/littlefs-project/littlefs"
        description = "Fail-safe filesystem designed for microcontrollers"
    strings:
        $a = /\x00lfs_file_\w+\x00/
        $b = /\x00lfs_dir_\w+\x00/
        $c = /\x00lfs_bd_\w+\x00/
    condition:
        2 of them
}

rule miniz {
    meta:
        software_name = "miniz"
        open_source = true
        website = "https://github.com/richgel999/miniz"
        description = "Single-file deflate/inflate, zlib and zip archive library"
    strings:
        $a = /\x00tdefl_\w+\x00/
        $b = /\x00tinfl_\w+\x00/
        $c = /\x00mz_(deflate|inflate|zip_\w+)\x00/
    condition:
        #a > 2 or #b > 1 or #c > 2
}

rule ecos {
    meta:
        software_name = "eCos"
        open_source = true
        website = "https://ecos.sourceware.org/"
        description = "Configurable real-time operating system for embedded devices"
    strings:
        $a = /\x00cyg_net_\w+\x00/
        $b = /\x00cyg_httpd_\w+\x00/
        $c = /\x00cyg_tcp_\w+\x00/
        $d = /\x00cyg_hal_\w+\x00/
        $e = /\x00cyg_ppp_\w+\x00/
    condition:
        2 of them
}

rule http_parser {
    meta:
        software_name = "http-parser"
        open_source = true
        website = "https://github.com/nodejs/http-parser"
        description = "HTTP request/response parser for C (deprecated, see llhttp)"
    strings:
        $a = /\x00http_parser_\w+\x00/
        $b = /\x00HPE_(INVALID|UNEXPECTED)_\w+\x00/
    condition:
        $a and #b > 1
}

rule llhttp {
    meta:
        software_name = "llhttp"
        open_source = true
        website = "https://github.com/nodejs/llhttp"
        description = "Modern HTTP parser, successor of http-parser"
    strings:
        $a = /\x00llhttp_\w+\x00/
        $b = /\x00HPE_(INVALID|UNEXPECTED|PAUSED|CB)_\w+\x00/
    condition:
        #a > 2 or ($a and #b > 1)
}

rule tlsf {
    meta:
        software_name = "TLSF"
        open_source = true
        website = "https://github.com/mattconte/tlsf"
        description = "Two-Level Segregated Fit memory allocator"
    strings:
        $a = /\x00tlsf_(create|malloc|free|realloc|memalign|add_pool|check)\w*\x00/
        $b = /\x00block_(next|split|merge|locate_free|trim_\w+)\w*\x00/
    condition:
        all of them
}

rule freertos {
    meta:
        software_name = "FreeRTOS"
        open_source = true
        website = "https://www.freertos.org"
        description = "Real-time operating system kernel for embedded devices"
    strings:
        $a = /\x00xTaskCreate\w*\x00/
        $b = /\x00vTaskDelay\w*\x00/
        $c = /\x00xQueue(Create|Send|Receive|Generic)\w*\x00/
        $d = /\x00pvPortMalloc\x00/
        $e = /\x00vTaskStartScheduler\x00/
    condition:
        2 of them
}

rule zephyr {
    meta:
        software_name = "Zephyr RTOS"
        open_source = true
        website = "https://www.zephyrproject.org"
        description = "Scalable real-time operating system for connected devices"
    strings:
        // zephyr unique
        $z0 = "Zephyr OS"
        $z1 = /\x00z_impl_k_\w+\x00/
        $z2 = /\x00z_swap\x00/
        $z3 = /\x00z_ready_thread\x00/
        // more generic
        $k1 = /\x00k_thread_\w+\x00/
        $k2 = /\x00k_sem_(give|take|init|reset)\w*\x00/
        $k3 = /\x00k_mutex_(lock|unlock|init)\w*\x00/
        $k4 = /\x00k_msgq_\w+\x00/
    condition:
        (1 of ($z*)) and (2 of ($k*))
}

rule mbedtls {
    meta:
        software_name = "Mbed TLS"
        open_source = true
        website = "https://github.com/Mbed-TLS/mbedtls"
        description = "TLS and cryptography library for embedded systems"
    strings:
        $a = /\x00mbedtls_ssl_\w+\x00/
        $b = /\x00mbedtls_x509_\w+\x00/
        $c = /\x00mbedtls_(aes|rsa|ecp|sha256)_\w+\x00/
        $d = /\x00mbedtls_pk_\w+\x00/
    condition:
        2 of them
}

rule wolfssl {
    meta:
        software_name = "wolfSSL"
        open_source = true
        website = "https://www.wolfssl.com"
        description = "Small, portable TLS/SSL library for embedded and RTOS environments"
    strings:
        $a = /\x00wolfSSL_\w+\x00/
        $b = /\x00wc_(AesEncrypt|Sha256|RsaPublic|ecc_\w+|Hash)\w*\x00/
        $c = /\x00wolfSSL_CTX_\w+\x00/
    condition:
        #a > 2 or ($a and $b) or $c
}

rule zlib {
    meta:
        software_name = "zlib"
        open_source = true
        website = "https://www.zlib.net"
        description = "General purpose lossless data compression library"
    strings:
        // https://www.zlib.net/manual.html
        // inflate
        $a01 = /\x00inflateInit2?\x00/
        $a02 = /\x00inflateSetDictionary\x00/
        $a03 = /\x00inflateGetDictionary\x00/
        $a04 = /\x00inflateSync\x00/
        $a05 = /\x00inflateCopy\x00/
        $a06 = /\x00inflateReset2?\x00/
        $a07 = /\x00inflatePrime\x00/
        $a08 = /\x00inflateMark\x00/
        $a09 = /\x00inflateGetHeader\x00/
        $a10 = /\x00inflateBackInit\x00/
        $a11 = /\x00inflateBack\x00/
        $a12 = /\x00inflateBackEnd\x00/
        // deflate
        $a13 = /\x00deflateSetDictionary\x00/
        $a14 = /\x00deflateGetDictionary\x00/
        $a15 = /\x00deflateEnd\x00/
        $a16 = /\x00deflateCopy\x00/
        $a17 = /\x00deflateParams\x00/
        $a18 = /\x00deflateReset\x00/
        $a19 = /\x00deflateTune\x00/
        $a20 = /\x00deflateBound\x00/
        $a21 = /\x00deflatePending\x00/
        $a22 = /\x00deflatePrime\x00/
        $a23 = /\x00deflateSetHeader\x00/
        // other
        $a24 = /\x00compressBound\x00/
        $a25 = /\x00uncompress2\x00/
        $a26 = /\x00adler32\x00/
        $v = /\x00zlibVersion\x00/
        $tag = /deflate \d\.\d+/
    condition:
        (5 of ($a*)) or $v or $tag
}

rule fatfs_chan {
    meta:
        software_name = "FatFs"
        open_source = true
        website = "http://elm-chan.org/fsw/ff/00index_e.html"
        description = "Generic FAT filesystem module by ChaN for small embedded systems"
    strings:
        $a1 = /\x00f_open\x00/
        $a2 = /\x00f_read\x00/
        $a3 = /\x00f_write\x00/
        $a4 = /\x00f_mount\x00/
        $a5 = /\x00f_opendir\x00/
        $a6 = /\x00f_readdir\x00/
        $a7 = /\x00f_mkdir\x00/
        $a8 = /\x00f_unlink\x00/
        $a9 = /\x00f_lseek\x00/
        $b = /\x00disk_(initialize|status|read|write|ioctl)\x00/
        $c = /\x00get_fattime\x00/
    condition:
        3 of ($a*) or ((2 of ($a*)) and ($b or $c))
}

rule sqlite {
    meta:
        software_name = "SQLite"
        open_source = true
        website = "https://www.sqlite.org"
        description = "Embedded SQL database engine"
    strings:
        $a = /\x00sqlite3_\w+\x00/
    condition:
        #a > 3
}

rule cjson {
    meta:
        software_name = "cJSON"
        open_source = true
        website = "https://github.com/DaveGamble/cJSON"
        description = "Ultralightweight JSON parser in C"
    strings:
        $a = /\x00cJSON_(Parse|Print|CreateObject|CreateArray|AddItemToObject|GetObjectItem|Delete)\w*\x00/
        $b = /\x00cJSON_\w+\x00/
    condition:
        $a and #b > 3
}

rule jsmn {
    meta:
        software_name = "jsmn"
        open_source = true
        website = "https://github.com/zserge/jsmn"
        description = "Minimalistic JSON parser (often header-only, may inline)"
    strings:
        $a = /\x00jsmn_(init|parse|parse_\w+|alloc_token|fill_token)\x00/
        $b = /\x00jsmn_\w+\x00/
    condition:
        #b > 1 and $a
}

rule json_c {
    meta:
        software_name = "json-c"
        open_source = true
        website = "https://github.com/json-c/json-c"
        description = "JSON implementation in C (json_object_* API)"
    strings:
        $a = /\x00json_object_new_(int|string|object|array|boolean|double)\x00/
        $b = /\x00json_object_object_(add|get|get_ex)\x00/
        $c = /\x00json_object_to_json_string(_ext)?\x00/
        $d = /\x00json_tokener_parse\x00/
        $e = /\x00json_object_put\x00/
        $f = /\x00json_object_get_(int|string|type|boolean)\x00/
    condition:
        3 of them
}

rule ccan_json {
    meta:
        software_name = "ccan/json"
        open_source = true
        website = "https://github.com/rustyrussell/ccan"
        description = "Kleine eingebettete JSON-Lib (json_mk*/encode/decode API)"
    strings:
        $mk1 = /\x00json_mk(string|number|bool|null|object|array)\x00/
        $mk2 = /\x00json_mk(longlong|ulonglong)\x00/
        $op1 = /\x00json_(encode|decode|stringify|validate|check)\x00/
        $op2 = /\x00json_(append|prepend)_(member|element)\x00/
        $op3 = /\x00json_find_(member|element)\x00/
        $h1 = /\x00emit_value(_indented)?\x00/
        $h2 = /\x00utf8_(read|write)_char\x00/
        $h3 = /\x00to_surrogate_pair\x00/
    condition:
        2 of ($mk*) and (1 of ($op*) or 1 of ($h*))
}

rule mongoose {
    meta:
        software_name = "Mongoose"
        open_source = true
        website = "https://mongoose.ws"
        description = "Embedded web server / networking library"
    strings:
        $a = /\x00mg_(mgr_init|listen|connect|http_\w+|mqtt_\w+|send|printf)\w*\x00/
        // Mongoose OS
        $b = /\x00mgos_\w+\x00/
        $c = "Mongoose/" ascii
    condition:
        #a > 2 or #b > 3 or $c
}

rule libcurl {
    meta:
        software_name = "libcurl"
        open_source = true
        website = "https://curl.se/libcurl/"
        description = "Client-side URL transfer library (HTTP, FTP, etc.)"
    strings:
        $a = /\x00curl_easy_\w+\x00/
        $b = /\x00curl_multi_\w+\x00/
        $c = /\x00curl_global_\w+\x00/
        $d = /\x00curl_slist_\w+\x00/
        $ver = "libcurl/" ascii
    condition:
        2 of ($a,$b,$c,$d) or ($a and $ver)
}

rule micro_ecc {
    meta:
        software_name = "micro-ecc"
        open_source = true
        website = "https://github.com/kmackay/micro-ecc"
        description = "Small, fast ECDH and ECDSA implementation for embedded systems"
    strings:
        $a = /\x00uECC_(make_key|shared_secret|sign|verify|compute_public_key|secp256r1|secp256k1|secp192r1)\w*\x00/
        $b = /\x00uECC_\w+\x00/
    condition:
        $a and #b > 1
}

rule nanopb {
    meta:
        software_name = "nanopb"
        open_source = true
        website = "https://github.com/nanopb/nanopb"
        description = "Small code-size Protocol Buffers implementation in C"
    strings:
        $a = /\x00pb_(encode|decode)\w*\x00/
        $b = /\x00pb_(ostream|istream)_from_\w+\x00/
        $c = /\x00pb_read\x00/
        $d = /\x00pb_write\x00/
    condition:
        $a and 1 of ($b,$c,$d)
}

rule libsodium {
    meta:
        software_name = "libsodium"
        open_source = true
        website = "https://libsodium.org"
        description = "Modern, easy-to-use crypto library (NaCl fork)"
    strings:
        // libsodium exclusive symbols
        $lib1 = /\x00sodium_init\x00/
        $lib2 = /\x00sodium_malloc\x00/
        $lib3 = /\x00sodium_memcmp\x00/
        $lib4 = /\x00sodium_version_string\x00/
        $lib5 = /\x00randombytes_buf\x00/
        $lib6 = /\x00crypto_pwhash\x00/
        $lib7 = /\x00crypto_aead_(chacha20poly1305|xchacha20poly1305)_\w+\x00/
        // generic NaCl-API (possibly contained in compatible libs like TweetNaCl or Monocypher)
        $nacl1 = /\x00crypto_sign(_detached|_open|_keypair|_verify_detached)?\x00/
        $nacl2 = /\x00crypto_box(_\w+)?\x00/
        $nacl3 = /\x00crypto_secretbox(_\w+)?\x00/
    condition:
        2 of ($lib*) or (1 of ($lib*) and 2 of ($nacl*))
}

rule tweetnacl {
    meta:
        software_name = "tweetnacl"
        open_source = true
        website = "https://tweetnacl.cr.yp.to"
        description = "auditable high-security cryptographic library with backwards compatibility to NaCl"
    strings:
        $a = /\x00crypto_\w{8,32}_tweet_\w+\x00/
        $b = /\x00crypto_\w{8,32}_tweet\x00/
    condition:
        any of them
}

rule libnacl {
    meta:
        software_name = "NaCl"
        open_source = true
        website = "https://https://nacl.cr.yp.to/"
        description = "easy-to-use high-speed crypto library, pronounced 'salt''"
    strings:
        $lib01 = /\x00crypto_sign(_\w+)?\x00/
        $lib02 = /\x00crypto_auth(_\w+)?\x00/
        $lib03 = /\x00crypto_box(_\w+)?\x00/
        $lib06 = /\x00crypto_hashblocks(_\w+)?\x00/
        $lib07 = /\x00crypto_onetimeauth(_\w+)?\x00/
        $lib08 = /\x00crypto_scalarmult(_\w+)?\x00/
        $lib09 = /\x00crypto_secretbox(_\w+)?\x00/
        $lib10 = /\x00crypto_hash(_\w+)?\x00/
        $lib11 = /\x00crypto_stream(_\w+)?\x00/
    condition:
        4 of them and not (tweetnacl or libsodium)
}

rule contiki_ng {
    meta:
        software_name = "Contiki-NG"
        open_source = true
        website = "https://www.contiki-ng.org"
        description = "Operating system for resource-constrained IoT devices"
    strings:
        $a = /\x00process_(start|post|poll|exit|run|alloc_event)\w*\x00/
        $b = /\x00ctimer_\w+\x00/
        $c = /\x00uip_\w+\x00/
        $d = /\x00etimer_\w+\x00/
        $e = /\x00tcpip_\w+\x00/
    condition:
        3 of them
}

rule libwebsockets {
    meta:
        software_name = "libwebsockets"
        open_source = true
        website = "https://libwebsockets.org"
        description = "Lightweight C library for WebSockets and related protocols"
    strings:
        $a = /\x00lws_(create_context|service|write|callback_\w+|client_connect|context_\w+)\w*\x00/
        $b = /\x00lws_\w+\x00/
    condition:
        ($a and #b > 3)
}

rule polarssl {
    meta:
        software_name = "PolarSSL"
        open_source = true
        website = "https://github.com/Mbed-TLS/mbedtls"
        description = "Legacy name of Mbed TLS (pre-2015); older embedded TLS stacks"
    strings:
        $a = /\x00ssl_(init|handshake|read|write|set_endpoint|free)\x00/
        $b = /\x00x509_crt_\w+\x00/
        $c = /\x00polarssl_\w+\x00/
        $d = /\x00POLARSSL_\w+\x00/
    condition:
        $c or $d or ($a and $b)
}

rule threadx_azure_rtos {
    meta:
        software_name = "ThreadX"
        open_source = true
        website = "https://github.com/eclipse-threadx/threadx"
        description = "Real-time operating system kernel (formerly Azure RTOS)"
    strings:
        $a = /\x00tx_thread_\w+\x00/
        $b = /\x00tx_queue_\w+\x00/
        $c = /\x00tx_semaphore_\w+\x00/
        $d = /\x00tx_mutex_\w+\x00/
        $e = /\x00tx_timer_\w+\x00/
        $f = /\x00tx_byte_pool_\w+\x00/
    condition:
        3 of them
}

rule chibios {
    meta:
        software_name = "ChibiOS"
        open_source = true
        website = "https://www.chibios.org"
        description = "Compact RTOS/HAL for embedded systems"
    strings:
        $a = /\x00chThdCreate\w+\x00/
        $b = /\x00chSem(Wait|Signal|Reset|Init|Object\w+)\w*\x00/
        $c = /\x00chMtx(Lock|Unlock|Init|Object\w+)\w*\x00/
        $d = /\x00chEvt(Wait|Signal|Register\w+|Broadcast\w+)\w*\x00/
        $e = /\x00chSysLock\x00/
        $f = /\x00chPoolAlloc\x00/
    condition:
        3 of them
}

rule riot_os {
    meta:
        software_name = "RIOT OS"
        open_source = true
        website = "https://www.riot-os.org"
        description = "OS for low-power IoT devices"
    strings:
        $b = /\x00gnrc_netif_\w+\x00/
        $c = /\x00gnrc_pktbuf_\w+\x00/
        $d = /\x00xtimer_\w+\x00/
        $e = /\x00gnrc_ipv6_\w+\x00/
        $f = /\x00gnrc_udp_\w+\x00/
    condition:
        3 of them
}

rule nuttx {
    meta:
        software_name = "NuttX"
        open_source = true
        website = "https://nuttx.apache.org"
        description = "POSIX-compliant RTOS for microcontrollers"
    strings:
        $a = /\x00nxsem_\w+\x00/
        $b = /\x00nxmutex_\w+\x00/
        $c = /\x00nxsig_\w+\x00/
        $d = /\x00nxtask_\w+\x00/
        $e = /\x00nxsched_\w+\x00/
    condition:
        3 of them
}

rule micropython {
    meta:
        software_name = "MicroPython"
        open_source = true
        website = "https://micropython.org"
        description = "Lean Python 3 implementation for microcontrollers"
    strings:
        $a = /\x00mp_obj_\w+\x00/
        $b = /\x00mp_parse_\w+\x00/
        $c = /\x00mp_compile_\w+\x00/
        $d = /\x00mp_emit_\w+\x00/
        $e = /\x00mp_hal_\w+\x00/
    condition:
        3 of them
}

/* ===================== Krypto / TLS ===================== */

rule bearssl {
    meta:
        software_name = "BearSSL"
        open_source = true
        website = "https://www.bearssl.org"
        description = "Small constant-time SSL/TLS implementation in C"
    strings:
        $a = /\x00br_ssl_\w+\x00/
        $b = /\x00br_x509_\w+\x00/
        $c = /\x00br_rsa_\w+\x00/
        $d = /\x00br_aes_\w+\x00/
        $e = /\x00br_hmac_\w+\x00/
    condition:
        3 of them
}

rule tinycrypt {
    meta:
        software_name = "TinyCrypt"
        open_source = true
        website = "https://github.com/intel/tinycrypt"
        description = "Small crypto library for constrained devices (since 2024 no longer maintained)"
    strings:
        $a = /\x00tc_aes_(encrypt|decrypt|set_\w+)\x00/
        $b = /\x00tc_sha256_\w+\x00/
        $c = /\x00tc_hmac_\w+\x00/
        $d = /\x00tc_ctr_prng_\w+\x00/
        $e = /\x00tc_ecc_\w+\x00/
    condition:
        3 of them
}

rule picotcp {
    meta:
        software_name = "picoTCP"
        open_source = true
        website = "https://github.com/tass-belgium/picotcp"
        description = "Small TCP/IP stack for embedded systems"
    strings:
        $a = /\x00pico_socket_\w+\x00/
        $b = /\x00pico_tcp_\w+\x00/
        $c = /\x00pico_ipv4_\w+\x00/
        $d = /\x00pico_frame_\w+\x00/
        $e = /\x00pico_dhcp_\w+\x00/
    condition:
        3 of them
}

rule libcoap {
    meta:
        software_name = "libcoap"
        open_source = true
        website = "https://libcoap.net"
        description = "CoAP (RFC 7252) implementation in C"
    strings:
        $a = /\x00coap_session_\w+\x00/
        $b = /\x00coap_pdu_\w+\x00/
        $c = /\x00coap_resource_\w+\x00/
        $d = /\x00coap_context_\w+\x00/
        $e = /\x00coap_endpoint_\w+\x00/
    condition:
        3 of them
}

rule paho_mqtt {
    meta:
        software_name = "Paho MQTT"
        open_source = true
        website = "https://github.com/eclipse/paho.mqtt.embedded-c"
        description = "Embedded MQTT C client/packet library"
    strings:
        $a = /\x00MQTTClient_\w+\x00/
        $b = /\x00MQTTSerialize_\w+\x00/
        $c = /\x00MQTTDeserialize_\w+\x00/
        $d = /\x00MQTTPacket_\w+\x00/
    condition:
        2 of them
}

rule mosquitto {
     meta:
         software_name = "Mosquitto"
         open_source = true
         website = "https://mosquitto.org"
         description = "MQTT broker and client library"
     strings:
         $a = /\x00mosquitto_\w+\x00/
     condition:
         #a > 5
}

rule openthread {
    meta:
        software_name = "OpenThread"
        open_source = true
        website = "https://openthread.io"
        description = "Open-source implementation of the Thread networking protocol"
    strings:
        $a = /\x00otThread\w+\x00/
        $b = /\x00otIp6\w+\x00/
        $c = /\x00otLink\w+\x00/
        $d = /\x00otMesh\w+\x00/
        $e = /\x00otBorderRouter\w+\x00/
    condition:
        3 of them
}

rule protobuf_c {
    meta:
        software_name = "protobuf-c"
        open_source = true
        website = "https://github.com/protobuf-c/protobuf-c"
        description = "Protocol Buffers implementation in C"
    strings:
        $a = /\x00protobuf_c_message_\w+\x00/
        $b = /\x00protobuf_c_buffer_\w+\x00/
        $c = /\x00protobuf_c_(service|enum|version)\w*\x00/
    condition:
        ($a and $b) or #a > 2 or (1 of ($a,$b) and $c)
}

rule msgpack_c {
    meta:
        software_name = "msgpack-c"
        open_source = true
        website = "https://github.com/msgpack/msgpack-c"
        description = "MessagePack serialization library for C/C++"
    strings:
        $a = /\x00msgpack_pack_\w+\x00/
        $b = /\x00msgpack_unpack_\w+\x00/
        $c = /\x00msgpack_sbuffer_\w+\x00/
    condition:
        2 of them
}

rule tinyusb {
    meta:
        software_name = "TinyUSB"
        open_source = true
        website = "https://github.com/hathach/tinyusb"
        description = "Cross-platform USB host/device stack for embedded systems"
    strings:
        $tusb = /\x00tusb_(init|inited|task|int_handler)\w*\x00/
        $tud = /\x00tud_(init|task|connected|mounted|cdc_\w+|hid_\w+|msc_\w+)\w*\x00/
        $tuh = /\x00tuh_(init|task|mounted|control_\w+)\w*\x00/
    condition:
        $tusb and 1 of ($tud,$tuh)
}

rule canopennode {
    meta:
        software_name = "CANopenNode"
        open_source = true
        website = "https://github.com/CANopenNode/CANopenNode"
        description = "CANopen protocol stack for embedded systems"
    strings:
        $a = /\x00CO_NMT_\w+\x00/
        $b = /\x00CO_SDO\w+\x00/
        $c = /\x00CO_PDO\w+\x00/
        $d = /\x00CO_CANmodule_\w+\x00/
        $e = /\x00CO_HBconsumer_\w+\x00/
    condition:
        3 of them
}

rule freemodbus {
    meta:
        software_name = "FreeMODBUS"
        open_source = true
        website = "https://github.com/cwalter-at/freemodbus"
        description = "Modbus ASCII/RTU/TCP protocol stack"
    strings:
        $anchor1 = /\x00eMBInit\x00/
        $anchor2 = /\x00eMBRegHoldingCB\x00/
        $anchor3 = /\x00eMBRegInputCB\x00/
        $anchor4 = /\x00eMBRegCoilsCB\x00/
        $gen1 = /\x00eMB(Enable|Disable|Poll|Close)\x00/
        $gen2 = /\x00xMBRTU\w+\x00/
    condition:
        1 of ($anchor*) and 1 of ($gen*)
}

// # teil 3

rule micrium_ucos {
    meta:
        software_name = "MicroC/OS"
        open_source = true
        website = "https://github.com/weston-embedded/uC-OS3"
        description = "Real-time kernel for embedded systems"
    strings:
        $a = /\x00OSTaskCreate\w*\x00/
        $b = /\x00OSSem(Pend|Post|Create|Del)\w*\x00/
        $c = /\x00OSMutex(Pend|Post|Create|Del)\w*\x00/
        $d = /\x00OSQ(Pend|Post|Create|Flush)\w*\x00/
        $e = /\x00OSTimeDly\w*\x00/
        $f = /\x00OSFlag(Pend|Post|Create)\w*\x00/
        $g = /\x00MicroC\/OS(-I{2,3})?\x00/
    condition:
        3 of them
}

rule micrium_uctcpip {
    meta:
        software_name = "uC/TCP-IP"
        open_source = true
        website = "https://github.com/weston-embedded/uC-TCP-IP"
        description = "TCP/IP stack for Micrium ecosystem"
    strings:
        $a = /\x00NetSock_\w+\x00/
        $b = /\x00NetIF_\w+\x00/
        $c = /\x00NetTCP_\w+\x00/
        $d = /\x00NetIP_\w+\x00/
        $e = /\x00NetASCII_\w+\x00/
    condition:
        3 of them
}

rule apache_mynewt {
    meta:
        software_name = "Apache Mynewt"
        open_source = true
        website = "https://mynewt.apache.org"
        description = "Modular RTOS for constrained embedded systems"
    strings:
        $a = /\x00os_task_\w+\x00/
        $b = /\x00os_mutex_\w+\x00/
        $c = /\x00os_mbuf_\w+\x00/
        $d = /\x00os_sem_\w+\x00/
        $e = /\x00os_eventq_\w+\x00/
        $f = /\x00os_callout_\w+\x00/
    condition:
        4 of them
}

rule segger_embos {
    meta:
        software_name = "embOS"
        open_source = false
        website = "https://www.segger.com/products/rtos/embos/"
        description = "Commercial priority-controlled RTOS from SEGGER"
    strings:
        $a = /\x00OS_TASK_\w+\x00/
        $b = /\x00OS_MUTEX_\w+\x00/
        $c = /\x00OS_EVENT_\w+\x00/
        $d = /\x00OS_MAILBOX_\w+\x00/
        $e = /\x00OS_SEMAPHORE_\w+\x00/
        $ver = /embOS[ _]V?\d+\.\d+/
    condition:
        $ver or 3 of ($a,$b,$c,$d,$e)
}

rule microrl {
    meta:
        software_name = "microrl"
        open_source = true
        website = "https://github.com/Helius/microrl"
        description = "Micro readline-like command line library for embedded"
    strings:
        $a = /\x00microrl_\w+\x00/
    condition:
        #a > 2
}

rule fnet {
    meta:
        software_name = "FNET"
        open_source = true
        website = "https://fnet.sourceforge.io"
        description = "Embedded TCP/IP stack (Kinetis/ARM)"
    strings:
        $a = /\x00fnet_socket\w*\x00/
        $b = /\x00fnet_netif_\w+\x00/
        $c = /\x00fnet_ip4_\w+\x00/
        $d = /\x00fnet_dhcp\w*\x00/
        $e = /\x00fnet_stack_\w+\x00/
    condition:
        3 of them
}

rule nanostack {
    meta:
        software_name = "Nanostack"
        open_source = true
        website = "https://github.com/PelionIoT/mbed-mesh-api"
        description = "6LoWPAN/Thread mesh networking stack"
    strings:
        $a = /\x00arm_nwk_\w+\x00/
        $b = /\x00arm_net_\w+\x00/
        $c = /\x00ns_sw_mac_\w+\x00/
        $d = /\x006lowpan_\w+\x00/
        $e = /\x00thread_management_\w+\x00/
    condition:
        3 of them
}

rule cyclone_tcp {
    meta:
        software_name = "CycloneTCP"
        open_source = true
        website = "https://www.oryx-embedded.com/products/CycloneTCP"
        description = "Dual IPv4/IPv6 TCP/IP stack for MCUs"
    strings:
        $ory = /Oryx Embedded/
        $a = /\x00tcpConnect\x00/
        $b = /\x00socketBind\x00/
        $c = /\x00ipv4SendDatagram\x00/
        $d = /\x00netGetDefaultInterface\x00/
        $e = /\x00ethSendFrame\x00/
    condition:
        $ory or 3 of ($a,$b,$c,$d,$e)
}

rule filex {
    meta:
        software_name = "FileX"
        open_source = true
        website = "https://github.com/eclipse-threadx/filex"
        description = "FAT-compatible file system for ThreadX"
    strings:
        $a = /\x00fx_media_\w+\x00/
        $b = /\x00fx_file_\w+\x00/
        $c = /\x00fx_directory_\w+\x00/
        $d = /\x00_fx_\w+\x00/
        $e = /\x00fx_system_\w+\x00/
    condition:
        3 of them
}

rule lwext4 {
    meta:
        software_name = "lwext4"
        open_source = true
        website = "https://github.com/gkostka/lwext4"
        description = "ext2/3/4 filesystem implementation for embedded"
    strings:
        $f01 = "\x00ext4_fopen\x00"
        $f02 = "\x00ext4_fclose\x00"
        $f03 = "\x00ext4_fread\x00"
        $f04 = "\x00ext4_fwrite\x00"
        $f05 = "\x00ext4_fseek\x00"
        $f06 = "\x00ext4_ftell\x00"
        $f07 = "\x00ext4_fsize\x00"
        $f08 = "\x00ext4_fremove\x00"
        $f09 = "\x00ext4_device_register\x00"
        $f10 = "\x00ext4_mount_point_stats\x00"
        $f11 = "\x00ext4_cache_write_back\x00"
        $f12 = "\x00ext4_dir_mk\x00"
        $f13 = "\x00ext4_dir_rm\x00"
        $f14 = "\x00ext4_dir_entry_rewind\x00"
    condition:
        4 of them
}

rule spiffs {
    meta:
        software_name = "SPIFFS"
        open_source = true
        website = "https://github.com/pellepl/spiffs"
        description = "SPI flash file system for embedded systems"
    strings:
        $a = /\x00SPIFFS_open\w*\x00/
        $b = /\x00SPIFFS_read\x00/
        $c = /\x00SPIFFS_write\x00/
        $d = /\x00SPIFFS_mount\x00/
        $e = /\x00SPIFFS_\w+\x00/
    condition:
        3 of them
}

rule nffs {
    meta:
        software_name = "NFFS"
        open_source = true
        website = "https://github.com/apache/mynewt-core"
        description = "NFFS (Newtron Flash File System) is the flash file system used in Apache Mynewt"
    strings:
        $a = /\x00nffs_open\x00/
        $b = /\x00nffs_read\x00/
        $c = /\x00nffs_write\x00/
        $d = /\x00nffs_format\x00/
        $e = /\x00nffs_\w+\x00/
    condition:
        3 of them
}

rule yaffs2 {
    meta:
        software_name = "YAFFS2"
        open_source = true
        website = "https://www.yaffs.net"
        description = "NAND flash file system"
    strings:
        $a = /\x00yaffs_mount\w*\x00/
        $b = /\x00yaffs_open\w*\x00/
        $c = /\x00yaffs_read\w*\x00/
        $d = /\x00yaffs_write\w*\x00/
        $e = /\x00yaffs_\w+\x00/
    condition:
        3 of them
}

rule uffs {
    meta:
        software_name = "UFFS"
        open_source = true
        website = "https://github.com/RQinTech/uffs"
        description = "UFFS (Ultra-low-cost Flash File System) is a NAND flash file system for embedded"
    strings:
        $a = /\x00uffs_Mount\w*\x00/
        $b = /\x00uffs_Open\w*\x00/
        $c = /\x00uffs_ReadFile\x00/
        $d = /\x00uffs_WriteFile\x00/
        $e = /\x00uffs_\w+\x00/
    condition:
        3 of them
}

rule reliance_edge {
    meta:
        software_name = "Reliance Edge"
        open_source = true
        website = "https://github.com/tuxera/reliance-edge"
        description = "Transactional file system for embedded devices"
    strings:
        $a = /\x00RedFse\w+\x00/
        $b = /\x00RedCore\w+\x00/
        $c = /\x00RedPosix\w+\x00/
        $d = /\x00red_(open|read|write|mount|format)\w*\x00/
        $e = /\x00RedVolume\w+\x00/
    condition:
        3 of them
}

rule cherryusb {
    meta:
        software_name = "CherryUSB"
        open_source = true
        website = "https://github.com/cherry-embedded/CherryUSB"
        description = "Tiny and portable USB host/device stack"
    strings:
        $cherry = /CherryUSB/
        $a = /\x00usbd_desc_register\x00/
        $b = /\x00usbd_add_interface\x00/
        $c = /\x00usbd_endpoint_register\x00/
        $d = /\x00usbh_initialize\x00/
        $e = /\x00chry_ringbuffer_\w+\x00/
    condition:
        $cherry or $e or 3 of ($a,$b,$c,$d)
}

rule tinydtls {
    meta:
        software_name = "tinydtls"
        open_source = true
        website = "https://github.com/eclipse/tinydtls"
        description = "DTLS implementation for constrained devices"
    strings:
        $a = /\x00dtls_connect\w*\x00/
        $b = /\x00dtls_write\x00/
        $c = /\x00dtls_handshake\w*\x00/
        $d = /\x00dtls_new_context\x00/
        $e = /\x00dtls_\w+\x00/
    condition:
        3 of them
}

rule wolfssh {
    meta:
        software_name = "wolfSSH"
        open_source = true
        website = "https://www.wolfssl.com/products/wolfssh/"
        description = "Lightweight SSHv2 library for embedded systems"
    strings:
        $a = /\x00wolfSSH_\w+\x00/
        $b = /\x00wolfSSH_connect\x00/
        $c = /\x00wolfSSH_SendPacket\x00/
    condition:
        #a > 3 or 2 of ($b,$c)
}

rule wolftpm {
    meta:
        software_name = "wolfTPM"
        open_source = true
        website = "https://www.wolfssl.com/products/wolftpm/"
        description = "Portable TPM 2.0 library for embedded systems"
    strings:
        $a = /\x00wolfTPM_\w+\x00/
        $b = /\x00TPM2_(Startup|Create|Load|GetCapability)\w*\x00/
    condition:
        #a > 2 or ($a and $b)
}

rule cyclone_ssh {
    meta:
        software_name = "CycloneSSH"
        open_source = true
        website = "https://www.oryx-embedded.com/products/CycloneSSH"
        description = "SSH client/server library for MCUs"
    strings:
        $ory = /Oryx Embedded/
        $a = /\x00sshConnect\x00/
        $b = /\x00sshServerInit\w*\x00/
        $c = /\x00sshCreateChannel\x00/
        $d = /\x00sshInitConnection\x00/
        $e = /\x00sshParsePacket\x00/
    condition:
        3 of them
}

rule cyclone_rtsp {
    meta:
        software_name = "CycloneRTSP"
        open_source = true
        website = "https://www.oryx-embedded.com"
        description = "RTSP streaming library for MCUs"
    strings:
        $a = /\x00rtspClient\w+\x00/
        $b = /\x00rtspServer\w+\x00/
        $c = /\x00rtspConnection\w+\x00/
        $d = /\x00rtspParse\w+\x00/
    condition:
        2 of them
}

rule cyclone_http {
    meta:
        software_name = "CycloneHTTP"
        open_source = true
        website = "https://www.oryx-embedded.com/products/CycloneHTTP"
        description = "HTTP client/server library for MCUs"
    strings:
        $ory = /Oryx Embedded/
        $a = /\x00httpServerInit\w*\x00/
        $b = /\x00httpServerStart\x00/
        $c = /\x00httpClientConnect\x00/
        $d = /\x00httpReadHeader\w*\x00/
        $e = /\x00httpWriteHeader\w*\x00/
    condition:
        $ory or 3 of ($a,$b,$c,$d,$e)
}

rule rstplib {
    meta:
        software_name = "rstplib"
        open_source = true
        website = "https://sourceforge.net/projects/rstplib/"
        description = "IEEE 802.1w Rapid Spanning Tree Protocol reference implementation"
    strings:
        // Port Role Selection State Machine
        $r1 = "ALTERNATE_PROPOSED"
        $r2 = "ALTERNATE_AGREED"
        $r3 = "ROOT_PROPOSED"
        $r4 = "ROOT_AGREED"
        $r5 = "ROOT_FORWARD"
        $r6 = "ROOT_LEARN"
        $r7 = "DESIGNATED_PROPOSE"
        $r8 = "DESIGNATED_SYNCED"
        $r9 = "DESIGNATED_RETIRED"
        $r10 = "DESIGNATED_FORWARD"
        $r11 = "DESIGNATED_LEARN"
        $r12 = "DESIGNATED_DISCARD"
        $r13 = "INFERIOR_DESIGNATED"
        $r14 = "REPEATED_DESIGNATED"
        $r15 = "NOT_DESIGNATED"
        $r16 = "ROLE_SELECTION"
        // Topology Change / Transmit State Machine
        $t1 = "NOTIFIED_TCN"
        $t2 = "NOTIFIED_TC"
        $t3 = "TRANSMIT_RSTP"
        $t4 = "TRANSMIT_CONFIG"
        $t5 = "TRANSMIT_TCN"
        $t6 = "TRANSMIT_PERIODIC"
        // Bridge/Port init & detection
        $s1 = "CHECKING_RSTP"
        $s2 = "SELECTING_STP"
        $s3 = "INIT_BRIDGE"
        $s4 = "PROPAGATING"
    condition:
        6 of ($r*) and (2 of ($t*) or 2 of ($s*))
}

rule VxWorks_s {
	meta:
		software_name = "VxWorks"
		open_source = false
		website = "http://www.windriver.com/products/vxworks/"
		description = "Real Time Operating System by WindRiver"
    strings:
        // https://www.ee.torontomu.ca/~courses/ee8205/Data-Sheets/Tornado-VxWorks/vxworks/ref
        // msgQLib
        $a01 = "\x00msgQCreate\x00"
        $a02 = "\x00msgQDelete\x00"
        $a03 = "\x00msgQSend\x00"
        $a04 = "\x00msgQReceive\x00"
        $a05 = "\x00msgQNumMsgs\x00"
        // taskLib
        $a06 = "\x00taskSpawn\x00"
        $a07 = "\x00taskInit\x00"
        $a08 = "\x00taskActivate\x00"
        $a09 = "\x00taskPrioritySet\x00"
        $a10 = "\x00taskLock\x00"
        $a11 = "\x00taskUnlock\x00"
        $a12 = "\x00taskDelay\x00"
        $a13 = "\x00taskSuspend\x00"
        $a14 = "\x00taskResume\x00"
        $a15 = "\x00taskName\x00"
        $a16 = "\x00taskNameToId\x00"
        $a17 = "\x00taskIdSelf\x00"
        $a18 = "\x00taskIdVerify\x00"
        $a19 = "\x00taskOptionsGet\x00"
        $a20 = "\x00taskIdListGet\x00"
        $a21 = "\x00taskInfoGet\x00"
        $a22 = "\x00taskPriorityGet\x00"
        $a23 = "\x00taskRegsGet\x00"
        $a24 = "\x00taskRegsSet\x00"
        $a25 = "\x00taskIsSuspended\x00"
        $a26 = "\x00taskIsReady\x00"
        $a27 = "\x00taskTcb\x00"
        $a28 = "\x00taskDelete\x00"
        $a29 = "\x00taskSafe\x00"
        $a30 = "\x00taskUnsafe\x00"
        $a31 = "\x00taskRestart\x00"
        // taskHookLib
        $a32 = "\x00taskCreateHookAdd\x00"
        $a33 = "\x00taskCreateHookDelete\x00"
        $a34 = "\x00taskSwitchHookAdd\x00"
        $a35 = "\x00taskSwitchHookDelete\x00"
        $a36 = "\x00taskDeleteHookAdd\x00"
        $a37 = "\x00taskDeleteHookDelete\x00"
        // eventLib
        $a38 = "\x00semEvStart\x00"
        $a39 = "\x00semEvStop\x00"
        $a40 = "\x00msgQEvStart\x00"
        $a41 = "\x00msgQEvStop\x00"
        // classes
        $b01 = "\x00VXWList\x00"
        $b02 = "\x00VXWMemPart\x00"
        $b03 = "\x00VXWModule\x00"
        $b04 = "\x00VXWMsgQ\x00"
        $b05 = "\x00VXWRingBuf\x00"
        $b06 = "\x00VXWSem\x00"
        $b07 = "\x00VXWSm\x00"
        $b08 = "\x00VXWSmName\x00"
        $b09 = "\x00VXWSymTab\x00"
        $b10 = "\x00VXWTask\x00"
        $b11 = "\x00VXWWd\x00"
        // Constants
        $c01 = "\x00VX_FP_TASK\x00"
        $c02 = "\x00VX_NO_STACK_FILL\x00"
        $c03 = "\x00VX_PRIVATE_ENV\x00"
        $c04 = "\x00VX_UNBREAKABLE\x00"
        $c05 = "\x00VX_DSP_TASK\x00"
        $c06 = "\x00VX_ALTIVEC_TASK\x00"
		$c07 = /\x00VXDCOM_\w+\x00/
	condition:
		7 of them
}

rule libpcap_s {
    meta:
        software_name = "libpcap"
        open_source = true
        website = "https://www.tcpdump.org"
        description = "Portable packet capture library (pcap)"
    strings:
        $core1 = /\x00pcap_create\x00/
        $core2 = /\x00pcap_activate\x00/
        $core3 = /\x00pcap_compile\x00/
        $core4 = /\x00pcap_setfilter\x00/
        $core5 = /\x00pcap_next_ex\x00/
        $core6 = /\x00pcap_lookupnet\x00/
        $set1  = /\x00pcap_set_promisc\x00/
        $set2  = /\x00pcap_set_snaplen\x00/
        $set3  = /\x00pcap_set_timeout\x00/
        $misc1 = /\x00pcap_geterr\x00/
        $misc2 = /\x00pcap_close\x00/
    condition:
        3 of ($core*) and (1 of ($set*) or 1 of ($misc*))
}

rule libnetfilter_conntrack {
    meta:
        software_name = "libnetfilter_conntrack"
        open_source = true
        website = "https://netfilter.org/projects/libnetfilter_conntrack/"
        description = "Userspace library for the in-kernel connection tracking state table"
    strings:
        $a = /\x00nfct_\w*\x00/
        $b = /\x00nfct_filter_\w*\x00/
    condition:
        #a > 4 and $b
}

rule jim_tcl {
    meta:
        software_name = "Jim Tcl"
        open_source = true
        website = "http://jim.tcl.tk"
        description = "Small-footprint Tcl interpreter"
    strings:
        $core1 = /\x00Jim_CreateInterp\x00/
        $core2 = /\x00Jim_FreeInterp\x00/
        $core3 = /\x00Jim_RegisterCoreCommands\x00/
        $core4 = /\x00Jim_EvalObj\x00/
        $core5 = /\x00Jim_EvalFile\x00/
        $obj1  = /\x00Jim_NewStringObj\x00/
        $obj2  = /\x00Jim_NewIntObj\x00/
        $obj3  = /\x00Jim_NewListObj\x00/
        $obj4  = /\x00Jim_NewDictObj\x00/
        $pkg1  = /\x00Jim_PackageProvide\x00/
        $pkg2  = /\x00Jim_PackageRequire\x00/
        $cmd1  = /\x00Jim_CreateCommand\x00/
    condition:
        2 of ($core*) or (1 of ($core*) and 2 of ($obj*, $pkg*, $cmd*))
}

rule miniupnpd {
    meta:
        software_name = "miniupnpd"
        open_source = true
        website = "http://miniupnp.free.fr"
        description = "Lightweight UPnP IGD / NAT-PMP daemon"
    strings:
        $name = /\x00miniupnpd?\x00/ nocase
        $a1 = /\x00AddPortMapping\x00/
        $a2 = /\x00DeletePortMapping\x00/
        $a3 = /\x00GetGenericPortMappingEntry\x00/
        $a4 = /\x00GetSpecificPortMappingEntry\x00/
        $a5 = /\x00GetExternalIPAddress\x00/
        $a6 = /\x00NewPortMappingDescription\x00/
    condition:
        $name and 1 of ($a*)
}

rule openssl {
    meta:
        software_name = "OpenSSL"
        open_source = true
        website = "https://www.openssl.org"
        description = "OpenSSL TLS/crypto toolkit"
    strings:
        $m0 = /OpenSSL [\d.]+/
        // >= 1.1
        $m1 = /\x00OPENSSL_init_ssl\x00/
        $m2 = /\x00OPENSSL_sk_(num|value|pop_free|new_null)\x00/
        $m3 = /\x00X509_VERIFY_PARAM_set1_host\x00/
        // 0.9.x / 1.0.x
        $l1 = /\x00RSA_EAY_(PRIVATE|PUBLIC)_(EN|DE)CRYPT\x00/
        $l2 = /\x00SSLEAY_RAND_BYTES\x00/
        $l3 = /\x00SSL23_(GET_CLIENT_HELLO|CONNECT|ACCEPT)\x00/
        $l4 = /\x00OPENSSL_ALLOW_PROXY_CERTS\x00/
        $l5 = /\x00CRYPTO_get_new_lockid\x00/
        // generic API
        $s1 = /\x00SSL_CTX_new\x00/
        $s2 = /\x00SSL3_(CONNECT|ACCEPT|GET_RECORD)\x00/
        $s3 = /\x00X509_STORE_add_cert\x00/
        $s4 = /\x00EVP_(DigestInit|CipherInit)(_ex)?\x00/
        $s5 = /\x00PEM_read_bio\x00/
    condition:
        1 of ($m*, $l*) and 2 of ($s*)
}

rule ortp {
    meta:
        software_name = "oRTP"
        open_source = true
        website = "https://gitlab.linphone.org/BC/public/ortp"
        description = "RTP/RTCP library (RFC 3550) from the Linphone project"
    strings:
        $a1 = "\x00ortp_ev_queue_new\x00"
        $a2 = "\x00ortp_scheduler_init\x00"
        $a3 = "\x00ortp_set_log_handler\x00"
        $a4 = "\x00ortp_global_stats_display\x00"
        $b = /\x00ortp_\w*\x00/
    condition:
        (1 of ($a*)) and #b > 3
}
