#include "KOReaderSyncClient.h"

#include <ArduinoJson.h>
#include <Logging.h>
#include <esp_crt_bundle.h>
#include <esp_http_client.h>
#include <mbedtls/base64.h>

#include "KOReaderCredentialStore.h"

int KOReaderSyncClient::lastHttpCode = 0;

namespace {
// Device identifier for CrossPoint reader
constexpr char DEVICE_NAME[] = "CrossPoint";
constexpr char DEVICE_ID[] = "crosspoint-reader";

// Use 2KB TLS buffers instead of Arduino's default 16KB RX + 16KB TX.
// After WiFi init the ESP32-C3 has ~46KB free heap; the 32KB default leaves
// insufficient headroom for the TLS handshake to complete reliably.
// KOSync payloads are small (<1KB), so 2KB buffers are sufficient.
constexpr int TLS_BUFFER_SIZE = 2048;
constexpr int MAX_RESPONSE_SIZE = 1024;

// Build a Base64-encoded HTTP Basic Auth header value.
// Credentials buffer: max 64 (user) + 1 (:) + 64 (pass) + null = 130 bytes.
// Base64 output: ceil(130/3)*4 + 1 = 177 bytes — fits on stack.
std::string buildBasicAuthHeader() {
  const std::string credentials = KOREADER_STORE.getUsername() + ":" + KOREADER_STORE.getPassword();
  const auto* src = reinterpret_cast<const unsigned char*>(credentials.c_str());
  const size_t srcLen = credentials.size();

  // First call with nullptr to obtain the required output length (includes null terminator).
  size_t outLen = 0;
  mbedtls_base64_encode(nullptr, 0, &outLen, src, srcLen);

  std::string encoded(outLen, '\0');
  mbedtls_base64_encode(reinterpret_cast<unsigned char*>(&encoded[0]), outLen, &outLen, src, srcLen);

  // mbedtls writes a null terminator and includes it in outLen — trim it.
  if (!encoded.empty() && encoded.back() == '\0') {
    encoded.pop_back();
  }
  return "Basic " + encoded;
}

bool setAuthHeaders(esp_http_client_handle_t client) {
  const std::string authHeader = buildBasicAuthHeader();
  if (esp_http_client_set_header(client, "Accept", "application/vnd.koreader.v1+json") != ESP_OK ||
      esp_http_client_set_header(client, "x-auth-user", KOREADER_STORE.getUsername().c_str()) != ESP_OK ||
      esp_http_client_set_header(client, "x-auth-key", KOREADER_STORE.getMd5Password().c_str()) != ESP_OK ||
      esp_http_client_set_header(client, "Authorization", authHeader.c_str()) != ESP_OK) {
    LOG_ERR("KOSync", "Failed to set auth headers");
    return false;
  }
  return true;
}

struct HttpResult {
  int statusCode = -1;
  std::string body;
};

HttpResult doGet(const std::string& url) {
  HttpResult result;

  esp_http_client_config_t config = {};
  config.url = url.c_str();
  config.crt_bundle_attach = esp_crt_bundle_attach;
  config.buffer_size = TLS_BUFFER_SIZE;
  config.buffer_size_tx = TLS_BUFFER_SIZE;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    LOG_ERR("KOSync", "Failed to create HTTP client");
    return result;
  }

  if (!setAuthHeaders(client)) {
    esp_http_client_cleanup(client);
    return result;
  }

  const esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    LOG_ERR("KOSync", "HTTP open failed: 0x%x", err);
    esp_http_client_cleanup(client);
    return result;
  }

  const int64_t contentLength = esp_http_client_fetch_headers(client);
  result.statusCode = esp_http_client_get_status_code(client);

  if (contentLength > 0 && contentLength <= MAX_RESPONSE_SIZE) {
    result.body.resize(static_cast<size_t>(contentLength));
    esp_http_client_read(client, &result.body[0], static_cast<int>(contentLength));
  } else if (contentLength < 0) {
    // Chunked or no Content-Length — read until the client signals completion.
    char buf[128];
    int bytesRead;
    while ((bytesRead = esp_http_client_read(client, buf, sizeof(buf))) > 0) {
      if (result.body.size() + static_cast<size_t>(bytesRead) < MAX_RESPONSE_SIZE) {
        result.body.append(buf, static_cast<size_t>(bytesRead));
      }
    }
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  return result;
}

HttpResult doPut(const std::string& url, const std::string& body) {
  HttpResult result;

  esp_http_client_config_t config = {};
  config.url = url.c_str();
  config.crt_bundle_attach = esp_crt_bundle_attach;
  config.buffer_size = TLS_BUFFER_SIZE;
  config.buffer_size_tx = TLS_BUFFER_SIZE;
  config.method = HTTP_METHOD_PUT;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    LOG_ERR("KOSync", "Failed to create HTTP client");
    return result;
  }

  if (!setAuthHeaders(client)) {
    esp_http_client_cleanup(client);
    return result;
  }

  if (esp_http_client_set_header(client, "Content-Type", "application/json") != ESP_OK) {
    LOG_ERR("KOSync", "Failed to set Content-Type header");
    esp_http_client_cleanup(client);
    return result;
  }

  const esp_err_t err = esp_http_client_open(client, static_cast<int>(body.size()));
  if (err != ESP_OK) {
    LOG_ERR("KOSync", "HTTP open failed: 0x%x", err);
    esp_http_client_cleanup(client);
    return result;
  }

  const int written = esp_http_client_write(client, body.c_str(), static_cast<int>(body.size()));
  if (written < 0) {
    LOG_ERR("KOSync", "HTTP write failed");
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return result;
  }

  esp_http_client_fetch_headers(client);
  result.statusCode = esp_http_client_get_status_code(client);

  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  return result;
}
}  // namespace

KOReaderSyncClient::Error KOReaderSyncClient::authenticate() {
  if (!KOREADER_STORE.hasCredentials()) {
    LOG_DBG("KOSync", "No credentials configured");
    return NO_CREDENTIALS;
  }

  const std::string url = KOREADER_STORE.getBaseUrl() + "/users/auth";
  LOG_DBG("KOSync", "Authenticating: %s", url.c_str());
  LOG_DBG("KOSync", "Free heap before auth: %d", ESP.getFreeHeap());

  const auto response = doGet(url);
  lastHttpCode = response.statusCode;
  LOG_DBG("KOSync", "Auth response: %d", response.statusCode);

  if (response.statusCode == 200) return OK;
  if (response.statusCode == 401) return AUTH_FAILED;
  if (response.statusCode < 0) return NETWORK_ERROR;
  return SERVER_ERROR;
}

KOReaderSyncClient::Error KOReaderSyncClient::getProgress(const std::string& documentHash,
                                                          KOReaderProgress& outProgress) {
  if (!KOREADER_STORE.hasCredentials()) {
    LOG_DBG("KOSync", "No credentials configured");
    return NO_CREDENTIALS;
  }

  const std::string url = KOREADER_STORE.getBaseUrl() + "/syncs/progress/" + documentHash;
  LOG_DBG("KOSync", "Getting progress: %s", url.c_str());

  const auto response = doGet(url);
  lastHttpCode = response.statusCode;
  LOG_DBG("KOSync", "Get progress response: %d", response.statusCode);

  if (response.statusCode == 200) {
    JsonDocument doc;
    const DeserializationError error = deserializeJson(doc, response.body);
    if (error) {
      LOG_ERR("KOSync", "JSON parse failed: %s", error.c_str());
      return JSON_ERROR;
    }

    outProgress.document = documentHash;
    outProgress.progress = doc["progress"].as<std::string>();
    outProgress.percentage = doc["percentage"].as<float>();
    outProgress.device = doc["device"].as<std::string>();
    outProgress.deviceId = doc["device_id"].as<std::string>();
    outProgress.timestamp = doc["timestamp"].as<int64_t>();

    LOG_DBG("KOSync", "Got progress: %.2f%% at %s", outProgress.percentage * 100, outProgress.progress.c_str());
    return OK;
  }

  if (response.statusCode == 401) return AUTH_FAILED;
  if (response.statusCode == 404) return NOT_FOUND;
  if (response.statusCode < 0) return NETWORK_ERROR;
  return SERVER_ERROR;
}

KOReaderSyncClient::Error KOReaderSyncClient::updateProgress(const KOReaderProgress& progress) {
  if (!KOREADER_STORE.hasCredentials()) {
    LOG_DBG("KOSync", "No credentials configured");
    return NO_CREDENTIALS;
  }

  const std::string url = KOREADER_STORE.getBaseUrl() + "/syncs/progress";
  LOG_DBG("KOSync", "Updating progress: %s", url.c_str());

  JsonDocument doc;
  doc["document"] = progress.document;
  doc["progress"] = progress.progress;
  doc["percentage"] = progress.percentage;
  doc["device"] = DEVICE_NAME;
  doc["device_id"] = DEVICE_ID;

  std::string body;
  serializeJson(doc, body);
  LOG_DBG("KOSync", "Request body: %s", body.c_str());

  const auto response = doPut(url, body);
  lastHttpCode = response.statusCode;
  LOG_DBG("KOSync", "Update progress response: %d", response.statusCode);

  if (response.statusCode == 200 || response.statusCode == 202) return OK;
  if (response.statusCode == 401) return AUTH_FAILED;
  if (response.statusCode < 0) return NETWORK_ERROR;
  return SERVER_ERROR;
}

KOReaderSyncClient::Error KOReaderSyncClient::registerUser() {
  if (!KOREADER_STORE.hasCredentials()) {
    LOG_DBG("KOSync", "No credentials configured");
    return NO_CREDENTIALS;
  }

  std::string url = KOREADER_STORE.getBaseUrl() + "/users/create";
  LOG_DBG("KOSync", "Registering user: %s", url.c_str());

  HTTPClient http;
  std::unique_ptr<WiFiClientSecure> secureClient;
  WiFiClient plainClient;

  if (isHttpsUrl(url)) {
    secureClient.reset(new WiFiClientSecure);
    secureClient->setInsecure();
    http.begin(*secureClient, url.c_str());
  } else {
    http.begin(plainClient, url.c_str());
  }
  addAuthHeaders(http);
  http.addHeader("Content-Type", "application/json");

  // POST with empty body; credentials are sent via auth headers
  const int httpCode = http.POST("");
  const String responseBody = http.getString();
  http.end();

  LOG_DBG("KOSync", "Register response: %d", httpCode);

  if (httpCode == 201) {
    return OK;
  } else if (httpCode == 200 || httpCode == 409) {
    // 200: korrosync returns 200 for existing user
    // 409: standard conflict response for duplicate user
    return USER_EXISTS;
  } else if (httpCode == 402) {
    // Some server variants return 402 for either "user exists" or "registration disabled".
    // Disambiguate by inspecting the response body.
    if (responseBody.indexOf("disabled") >= 0 || responseBody.indexOf("not allowed") >= 0) {
      return REGISTRATION_DISABLED;
    }
    return USER_EXISTS;
  } else if (httpCode < 0) {
    return NETWORK_ERROR;
  }
  return SERVER_ERROR;
}

const char* KOReaderSyncClient::errorString(Error error) {
  switch (error) {
    case OK:
      return "Success";
    case NO_CREDENTIALS:
      return "No credentials configured";
    case NETWORK_ERROR:
      return "Network error";
    case AUTH_FAILED:
      return "Authentication failed";
    case SERVER_ERROR:
      return "Server error (try again later)";
    case JSON_ERROR:
      return "JSON parse error";
    case NOT_FOUND:
      return "No progress found";
    case USER_EXISTS:
      return "Username already taken";
    case REGISTRATION_DISABLED:
      return "Registration is disabled on this server";
    default:
      return "Unknown error";
  }
}
