#include "otlp_log_exporter.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>

#include <curl/curl.h>

namespace {

constexpr size_t kMaxBatchRecords = 200;
constexpr size_t kMaxBufferedRecords = 4000;
constexpr auto kFlushInterval = std::chrono::seconds(10);
constexpr long kPostTimeoutSeconds = 15;

/*
 * There is deliberately no thread_local anything on this path.
 *
 * An earlier version of this exporter, in another app, marked the worker
 * thread with a `thread_local bool`. On this platform that crashed the process
 * the instant the worker started: the generated code reads the thread pointer
 * and offsets into it,
 *
 *     mrs  x0, TPIDR_EL0
 *     add  x0, x0, #0x10
 *     strb w1, [x0]        <- data abort, TPIDR_EL0 was 0
 *
 * TPIDR_EL0 is zero on a thread spawned this way. Do not reintroduce it.
 *
 * The invariant it guarded still holds by construction: nothing reachable from
 * onLogLine() or worker() calls brls::Logger. It has to stay that way.
 * Borealis fires the log event from inside Logger::log() while logMtx is held,
 * so logging from the callback would deadlock on a non recursive mutex, and a
 * failed export that logged its own failure would generate the record that
 * causes the next failure. Counters only, read by the main thread.
 */

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::string readFirstLine(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    std::string line;
    std::getline(file, line);
    return trim(line);
}

std::vector<std::pair<std::string, std::string>>
parseKeyValueList(const std::string& text) {
    std::vector<std::pair<std::string, std::string>> pairs;
    size_t position = 0;

    while (position <= text.size()) {
        const auto comma = text.find(',', position);
        const std::string item = trim(text.substr(
            position, comma == std::string::npos ? std::string::npos
                                                 : comma - position));
        if (!item.empty()) {
            const auto equals = item.find('=');
            if (equals != std::string::npos && equals > 0) {
                pairs.emplace_back(trim(item.substr(0, equals)),
                                   trim(item.substr(equals + 1)));
            }
        }
        if (comma == std::string::npos) {
            break;
        }
        position = comma + 1;
    }

    return pairs;
}

/**
 * Appends value to out as the contents of a JSON string.
 *
 * Hand rolled rather than pulling in a JSON library: this app links json-c
 * only conditionally, and the payload shape is fixed, so the only thing that
 * genuinely needs care is escaping. Unit tested on a host over quotes,
 * backslashes, newlines, tabs, ANSI escapes and UTF-8.
 */
void appendEscaped(std::string& out, const std::string& value) {
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                // Control characters must be escaped. Borealis log lines can
                // carry ANSI colour sequences, which start with 0x1b.
                char buffer[7];
                std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
                out += buffer;
            } else {
                // 0x20 and above pass through, including UTF-8 continuation
                // bytes, which are already valid inside a JSON string.
                out += static_cast<char>(ch);
            }
            break;
        }
    }
}

void appendStringAttribute(std::string& out, const std::string& key,
                           const std::string& value) {
    out += "{\"key\":\"";
    appendEscaped(out, key);
    out += "\",\"value\":{\"stringValue\":\"";
    appendEscaped(out, value);
    out += "\"}}";
}

int severityNumber(brls::LogLevel level) {
    switch (level) {
    case brls::LogLevel::LOG_ERROR: return 17;   // ERROR
    case brls::LogLevel::LOG_WARNING: return 13; // WARN
    case brls::LogLevel::LOG_DEBUG: return 5;    // DEBUG
    case brls::LogLevel::LOG_VERBOSE: return 1;  // TRACE
    case brls::LogLevel::LOG_INFO:
    default: return 9;                           // INFO
    }
}

const char* severityText(brls::LogLevel level) {
    switch (level) {
    case brls::LogLevel::LOG_ERROR: return "ERROR";
    case brls::LogLevel::LOG_WARNING: return "WARN";
    case brls::LogLevel::LOG_DEBUG: return "DEBUG";
    case brls::LogLevel::LOG_VERBOSE: return "TRACE";
    case brls::LogLevel::LOG_INFO:
    default: return "INFO";
    }
}

size_t discardResponse(void*, size_t size, size_t nmemb, void*) {
    return size * nmemb;
}

} // namespace

OtlpLogExporter& OtlpLogExporter::instance() {
    static OtlpLogExporter exporter;
    return exporter;
}

OtlpLogExporter::~OtlpLogExporter() { stop(); }

bool OtlpLogExporter::start(const std::string& configDir) {
    if (m_enabled) {
        return true;
    }

    std::string endpoint = readFirstLine(configDir + "/otel-endpoint");
    if (endpoint.empty()) {
        return false;
    }

    while (!endpoint.empty() && endpoint.back() == '/') {
        endpoint.pop_back();
    }
    if (endpoint.size() < 8 || endpoint.compare(0, 8, "https://") != 0) {
        // Refuse plaintext. Headers routinely carry a credential.
        return false;
    }
    if (endpoint.size() < 8 ||
        endpoint.compare(endpoint.size() - 8, 8, "/v1/logs") != 0) {
        endpoint += "/v1/logs";
    }

    // Optional. Akira links curl with the libnx TLS backend, which validates
    // against the console's own trust store, so a bundle is usually
    // unnecessary. Peer verification stays on regardless.
    const std::string caBundlePath = configDir + "/cacert.pem";
    {
        std::ifstream caBundle(caBundlePath);
        if (caBundle.is_open()) {
            m_caBundlePath = caBundlePath;
        }
    }

    // Initialise curl on the main thread, before the worker exists.
    // curl_easy_init() lazily calls curl_global_init(), which is not thread
    // safe, so a worker racing the app's own curl setup is a real hazard.
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        return false;
    }

    m_endpoint = endpoint;
    m_headers = parseKeyValueList(readFirstLine(configDir + "/otel-headers"));
    m_resourceAttributes =
        parseKeyValueList(readFirstLine(configDir + "/otel-resource-attributes"));

    const bool hasServiceName =
        std::any_of(m_resourceAttributes.begin(), m_resourceAttributes.end(),
                    [](const std::pair<std::string, std::string>& attribute) {
                        return attribute.first == "service.name";
                    });
    if (!hasServiceName) {
        m_resourceAttributes.emplace_back("service.name", "akira");
    }

    m_enabled = true;
    m_stopping = false;

    m_subscription = brls::Logger::getLogEvent()->subscribe(
        [this](brls::Logger::TimePoint when, brls::LogLevel level,
               const std::string& line) { this->onLogLine(when, level, line); });
    m_subscribed = true;

    m_thread = std::thread([this] { this->worker(); });

    return true;
}

void OtlpLogExporter::stop() {
    if (!m_enabled) {
        return;
    }

    if (m_subscribed) {
        brls::Logger::getLogEvent()->unsubscribe(m_subscription);
        m_subscribed = false;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stopping = true;
    }
    m_wake.notify_all();

    if (m_thread.joinable()) {
        m_thread.join();
    }

    m_enabled = false;
    m_headers.clear();
    curl_global_cleanup();
}

void OtlpLogExporter::onLogLine(brls::Logger::TimePoint when,
                                brls::LogLevel level, const std::string& line) {
    Record record;
    record.timeUnixNano = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            when.time_since_epoch())
            .count());
    record.severityNumber = severityNumber(level);
    record.severityText = severityText(level);
    record.body = line;

    bool overflowed = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_records.size() >= kMaxBufferedRecords) {
            m_records.pop_front();
            overflowed = true;
        }
        m_records.push_back(std::move(record));
    }

    // m_statsMutex is never taken while m_mutex is held. The worker needs both
    // as well, and opposite orders on the two threads would deadlock.
    {
        std::lock_guard<std::mutex> statsLock(m_statsMutex);
        m_stats.accepted++;
        if (overflowed) {
            m_stats.droppedOverflow++;
        }
    }
}

void OtlpLogExporter::worker() {
    for (;;) {
        std::deque<Record> batch;

        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_wake.wait_for(lock, kFlushInterval,
                            [this] { return m_stopping.load(); });

            const size_t take = std::min(m_records.size(), kMaxBatchRecords);
            for (size_t i = 0; i < take; i++) {
                batch.push_back(std::move(m_records.front()));
                m_records.pop_front();
            }

            if (batch.empty() && m_stopping) {
                return;
            }
        }

        if (batch.empty()) {
            continue;
        }

        const std::string payload = buildPayload(batch);
        const bool ok = !payload.empty() && post(payload);

        // Scoped so m_statsMutex is released before m_mutex is taken below.
        {
            std::lock_guard<std::mutex> statsLock(m_statsMutex);
            if (ok) {
                m_stats.sent += batch.size();
            } else {
                // Dropped rather than requeued. Requeuing a batch that failed
                // because the network is down grows the buffer without bound
                // and starves the newer records describing what happened.
                m_stats.droppedFailed += batch.size();
                m_stats.postFailures++;
            }
        }

        if (m_stopping) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_records.empty()) {
                return;
            }
        }
    }
}

std::string
OtlpLogExporter::buildPayload(const std::deque<Record>& batch) const {
    std::string out;
    out.reserve(batch.size() * 160);

    out += "{\"resourceLogs\":[{\"resource\":{\"attributes\":[";
    for (size_t i = 0; i < m_resourceAttributes.size(); i++) {
        if (i) {
            out += ',';
        }
        appendStringAttribute(out, m_resourceAttributes[i].first,
                              m_resourceAttributes[i].second);
    }
    out += "]},\"scopeLogs\":[{\"logRecords\":[";

    for (size_t i = 0; i < batch.size(); i++) {
        const Record& record = batch[i];
        if (i) {
            out += ',';
        }
        // timeUnixNano is a string in the OTLP JSON mapping: it is a uint64
        // and JSON numbers cannot carry that range safely.
        out += "{\"timeUnixNano\":\"";
        out += std::to_string(record.timeUnixNano);
        out += "\",\"severityNumber\":";
        out += std::to_string(record.severityNumber);
        out += ",\"severityText\":\"";
        out += record.severityText;
        out += "\",\"body\":{\"stringValue\":\"";
        appendEscaped(out, record.body);
        out += "\"}}";
    }

    out += "]}]}]}";
    return out;
}

bool OtlpLogExporter::post(const std::string& body) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    for (const auto& header : m_headers) {
        // Values may be credentials. They go on the wire and nowhere else.
        const std::string line = header.first + ": " + header.second;
        headers = curl_slist_append(headers, line.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, m_endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, kPostTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, kPostTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discardResponse);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (!m_caBundlePath.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, m_caBundlePath.c_str());
    }

    const CURLcode result = curl_easy_perform(curl);
    long status = 0;
    if (result == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    const bool ok = result == CURLE_OK && status >= 200 && status < 300;
    if (!ok) {
        // Recorded, never logged from here. The main thread reports it.
        std::lock_guard<std::mutex> lock(m_statsMutex);
        if (result != CURLE_OK) {
            m_lastError = std::string("curl: ") + curl_easy_strerror(result);
        } else {
            m_lastError = "endpoint returned HTTP " + std::to_string(status);
        }
    }

    return ok;
}

OtlpLogExporter::Stats OtlpLogExporter::stats() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

std::string OtlpLogExporter::lastError() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_lastError;
}
