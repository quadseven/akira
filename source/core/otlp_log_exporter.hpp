#pragma once

#include <atomic>
#include <borealis.hpp>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

/**
 * Exports borealis log lines over OTLP/HTTP.
 *
 * Vendor neutral by design: OTLP is JSON over HTTPS, so this talks to any OTLP
 * log endpoint, whether that is an OpenTelemetry Collector on your own network
 * or a hosted backend. Configuration follows the OpenTelemetry environment
 * variable conventions, read from files because a Switch has no environment.
 *
 *   sdmc:/switch/akira/otel-endpoint             OTEL_EXPORTER_OTLP_ENDPOINT
 *   sdmc:/switch/akira/otel-headers              OTEL_EXPORTER_OTLP_HEADERS
 *   sdmc:/switch/akira/otel-resource-attributes  OTEL_RESOURCE_ATTRIBUTES
 *   sdmc:/switch/akira/cacert.pem                optional CA bundle
 *
 * With no endpoint file this does nothing: no thread, no subscription, no
 * allocation.
 *
 * The CA bundle is optional here, unlike a build using mbedtls. Akira links a
 * curl built with the libnx TLS backend, which validates against the console's
 * own trust store, so there is usually nothing to supply. Peer verification is
 * never disabled either way; if the handshake fails the reason is recorded and
 * reported rather than worked around.
 */
class OtlpLogExporter {
  public:
    static OtlpLogExporter& instance();

    bool start(const std::string& configDir);
    void stop();

    [[nodiscard]] bool enabled() const { return m_enabled; }
    [[nodiscard]] std::string endpoint() const { return m_endpoint; }

    struct Stats {
        size_t accepted;
        size_t sent;
        size_t droppedOverflow;
        size_t droppedFailed;
        size_t postFailures;
    };

    [[nodiscard]] Stats stats() const;

    /**
     * Last transport failure, or empty. Recorded rather than logged: nothing
     * on the worker path may call brls::Logger. Read it from the main thread.
     */
    [[nodiscard]] std::string lastError() const;

  private:
    OtlpLogExporter() = default;
    ~OtlpLogExporter();

    OtlpLogExporter(const OtlpLogExporter&) = delete;
    OtlpLogExporter& operator=(const OtlpLogExporter&) = delete;

    struct Record {
        uint64_t timeUnixNano;
        int severityNumber;
        const char* severityText;
        std::string body;
    };

    void onLogLine(brls::Logger::TimePoint when, brls::LogLevel level,
                   const std::string& line);
    void worker();
    bool post(const std::string& body);
    [[nodiscard]] std::string buildPayload(const std::deque<Record>& batch) const;

    bool m_enabled = false;

    std::string m_endpoint;
    std::string m_caBundlePath; // empty means use the TLS backend's own store
    // Header values may carry credentials. Never logged, never returned.
    std::vector<std::pair<std::string, std::string>> m_headers;
    std::vector<std::pair<std::string, std::string>> m_resourceAttributes;

    mutable std::mutex m_mutex;
    std::condition_variable m_wake;
    std::deque<Record> m_records;
    std::atomic<bool> m_stopping { false };

    std::thread m_thread;
    brls::Event<brls::Logger::TimePoint, brls::LogLevel,
                std::string>::Subscription m_subscription;
    bool m_subscribed = false;

    mutable std::mutex m_statsMutex;
    Stats m_stats {};
    std::string m_lastError;
};
