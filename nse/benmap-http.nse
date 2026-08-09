local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local math_abs = math.abs
local math_floor = math.floor
local math_log = math.log
local string_format = string.format

local REGISTRY_KEY = "benmap.http.v1"
local REGISTRY_MUTEX = nmap.mutex(REGISTRY_KEY)
local LOG_10 = math_log(10)

local BENFORD = {}
for digit = 1, 9 do
  BENFORD[digit] = math_log(1 + (1 / digit)) / LOG_10
end

description = [[
Collects controlled HTTP response measurements for Benmap and reports a scan-wide,
eligibility-gated first-digit Benford summary.

The script records application elapsed time, declared content length, complete body
size when available, and Nmap host timing metadata. It does not treat Benford
deviation as evidence of compromise. Cohorts that lack sufficient samples, numeric
span, or diversity are explicitly marked not evaluated.
]]

author = "Alec Akin and Benmap contributors"
license = "MIT"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap -sV --script ./nse/benmap-http.nse -oX scan.xml <target>
--
-- @args benmap-http.path HTTP path to request. Default: <code>/</code>.
-- @args benmap-http.method Initial request method: <code>HEAD</code> or
--   <code>GET</code>. Default: <code>HEAD</code>.
-- @args benmap-http.fallback-get When the initial HEAD request fails or lacks a
--   Content-Length header, make one bounded GET request. Default: <code>true</code>.
-- @args benmap-http.max-body-size Maximum GET body bytes retained by Nmap's HTTP
--   library. Truncated bodies are recorded but excluded from complete-body-size
--   analysis. Default: <code>65536</code>.
-- @args benmap-http.timeout Per-request timeout, expressed as an Nmap time
--   specification such as <code>5s</code> or <code>750ms</code>. By default the
--   timeout is derived from Nmap's host timing data and capped at 8 seconds.
-- @args benmap-http.redirects Number of same-origin redirects to follow. Default:
--   <code>0</code>.
-- @args benmap-http.min-samples Minimum positive observations required for the
--   scan-wide Benford calculation. Default: <code>200</code>.
-- @args benmap-http.min-orders Minimum decimal orders of magnitude required for
--   the scan-wide Benford calculation. Default: <code>2</code>.
-- @args benmap-http.min-unique-values Minimum number of distinct values required.
--   Default: <code>9</code>.
-- @args benmap-http.min-unique-ratio Minimum fraction of distinct values required.
--   Default: <code>0.05</code>.
-- @args benmap-http.show-digits Include all nine observed and expected digit bins
--   in post-scan output. Default: <code>false</code>.
--
-- @output
-- PORT     STATE SERVICE
-- 443/tcp  open  https
-- | benmap-http:
-- |   schema: benmap.http.observation.v1
-- |   target: 192.0.2.10
-- |   method: HEAD
-- |   status: 200
-- |   elapsed_us: 18421
-- |_  content_length: 4096
---

portrule = shortport.http

postrule = function()
  local state = nmap.registry[REGISTRY_KEY]
  return state ~= nil and state.observations ~= nil and #state.observations > 0
end

local function round(value, decimals)
  if value == nil then
    return nil
  end
  local multiplier = 10 ^ (decimals or 0)
  if value >= 0 then
    return math_floor((value * multiplier) + 0.5) / multiplier
  end
  return -math_floor((-value * multiplier) + 0.5) / multiplier
end

local function parse_boolean(value, default)
  if value == nil then
    return default
  end
  if value == true or value == 1 then
    return true
  end

  local normalized = tostring(value):lower()
  if normalized == "true" or normalized == "yes" or normalized == "on" or normalized == "1" then
    return true
  end
  if normalized == "false" or normalized == "no" or normalized == "off" or normalized == "0" then
    return false
  end

  return default
end

local function parse_number_arg(name, default, minimum, maximum)
  local raw = stdnse.get_script_args(name)
  if raw == nil then
    return default
  end

  local parsed = tonumber(raw)
  if parsed == nil then
    stdnse.debug(1, "%s: invalid numeric value %q; using %s", name, tostring(raw), tostring(default))
    return default
  end
  if minimum ~= nil and parsed < minimum then
    stdnse.debug(1, "%s: value below minimum %s; using %s", name, tostring(minimum), tostring(default))
    return default
  end
  if maximum ~= nil and parsed > maximum then
    stdnse.debug(1, "%s: value above maximum %s; using %s", name, tostring(maximum), tostring(default))
    return default
  end

  return parsed
end

local function parse_timeout_ms(host)
  local raw = stdnse.get_script_args("benmap-http.timeout")
  if raw == nil then
    return stdnse.get_timeout(host, 8000, 1000)
  end

  local seconds, parse_error = stdnse.parse_timespec(tostring(raw))
  if seconds == nil then
    stdnse.debug(1, "benmap-http.timeout: %s; using Nmap-derived timeout", tostring(parse_error))
    return stdnse.get_timeout(host, 8000, 1000)
  end

  return math.max(10, math_floor((seconds * 1000) + 0.5))
end

local function load_request_config(host)
  local method = tostring(stdnse.get_script_args("benmap-http.method") or "HEAD"):upper()
  if method ~= "HEAD" and method ~= "GET" then
    stdnse.debug(1, "benmap-http.method: expected HEAD or GET; using HEAD")
    method = "HEAD"
  end

  local path = tostring(stdnse.get_script_args("benmap-http.path") or "/")
  if path == "" then
    path = "/"
  elseif path:sub(1, 1) ~= "/" then
    path = "/" .. path
  end

  return {
    method = method,
    path = path,
    fallback_get = parse_boolean(stdnse.get_script_args("benmap-http.fallback-get"), true),
    max_body_size = math_floor(parse_number_arg("benmap-http.max-body-size", 65536, 1, 16777216)),
    timeout_ms = parse_timeout_ms(host),
    redirects = math_floor(parse_number_arg("benmap-http.redirects", 0, 0, 10)),
  }
end

local function load_summary_config()
  return {
    min_samples = math_floor(parse_number_arg("benmap-http.min-samples", 200, 1, 100000000)),
    min_orders = parse_number_arg("benmap-http.min-orders", 2.0, 0, 100),
    min_unique_values = math_floor(parse_number_arg("benmap-http.min-unique-values", 9, 1, 100000000)),
    min_unique_ratio = parse_number_arg("benmap-http.min-unique-ratio", 0.05, 0, 1),
    show_digits = parse_boolean(stdnse.get_script_args("benmap-http.show-digits"), false),
  }
end

local function make_request(host, port, method, config)
  local options = {
    bypass_cache = true,
    no_cache = true,
    no_cache_body = true,
    max_body_size = config.max_body_size,
    truncated_ok = true,
    timeout = config.timeout_ms,
    redirect_ok = config.redirects > 0 and config.redirects or false,
    header = {
      ["Accept"] = "*/*",
      ["Accept-Encoding"] = "identity",
    },
  }

  local started_us = stdnse.clock_us()
  local response
  if method == "HEAD" then
    response = http.head(host, port, config.path, options)
  else
    response = http.get(host, port, config.path, options)
  end
  local elapsed_us = math.max(0, stdnse.clock_us() - started_us)

  return response, elapsed_us
end

local function parse_content_length(response)
  if response == nil or response.header == nil then
    return nil
  end

  local raw = response.header["content-length"]
  if raw == nil then
    return nil
  end

  local digits = tostring(raw):match("^%s*(%d+)%s*$")
  if digits == nil then
    return nil
  end
  return tonumber(digits)
end

local function should_fallback_to_get(response, config)
  if config.method ~= "HEAD" or not config.fallback_get then
    return false
  end
  if response == nil or response.status == nil then
    return true
  end

  local status = tonumber(response.status)
  if status == 405 or status == 501 then
    return true
  end

  return parse_content_length(response) == nil
end

local function sanitize_error(value)
  if value == nil then
    return nil
  end
  local clean = tostring(value):gsub("[%r%n]+", " "):gsub("%s+$", "")
  if clean == "" then
    return nil
  end
  return clean
end

local function response_error(response)
  if response == nil then
    return "HTTP library returned no response"
  end
  if response.status ~= nil then
    return nil
  end
  return sanitize_error(response["status-line"]) or "HTTP request did not return a status code"
end

local function is_tls_service(port)
  if port.version ~= nil and port.version.service_tunnel == "ssl" then
    return true
  end

  local service = tostring(port.service or ""):lower()
  return service == "https" or service:match("^ssl/") ~= nil
end

local function body_length(value)
  if type(value) == "string" then
    return #value
  end
  return nil
end

local function build_observation(host, port, response, request_metadata, config)
  local truncated = response ~= nil and response.truncated == true
  local decoded_body_bytes = response ~= nil and body_length(response.body) or nil
  local raw_body_bytes = response ~= nil and body_length(response.rawbody) or nil
  local success = response ~= nil and response.status ~= nil
  local observation = {
    schema = "benmap.http.observation.v1",
    target = host.ip,
    hostname = stdnse.get_hostname(host),
    port = port.number,
    protocol = port.protocol,
    service = port.service or "unknown",
    tls = is_tls_service(port) and 1 or 0,
    path = config.path,
    method = request_metadata.method,
    success = success and 1 or 0,
    status = success and tonumber(response.status) or nil,
    error = success and nil or response_error(response),
    elapsed_us = request_metadata.elapsed_us,
    total_elapsed_us = request_metadata.total_elapsed_us,
    attempts = request_metadata.attempts,
    fallback_used = request_metadata.fallback_used and 1 or 0,
    content_length = parse_content_length(response),
    body_truncated = truncated and 1 or 0,
    body_bytes_observed = decoded_body_bytes,
    raw_body_bytes_observed = raw_body_bytes,
    content_type = response ~= nil and response.header ~= nil and response.header["content-type"] or nil,
    server = response ~= nil and response.header ~= nil and response.header["server"] or nil,
    redirects_followed = response ~= nil and type(response.location) == "table" and #response.location or 0,
  }

  if not truncated then
    observation.body_bytes = decoded_body_bytes
    observation.raw_body_bytes = raw_body_bytes
  end

  if host.times ~= nil then
    if host.times.srtt ~= nil then
      observation.nmap_srtt_us = math_floor((host.times.srtt * 1000000) + 0.5)
    end
    if host.times.rttvar ~= nil then
      observation.nmap_rttvar_us = math_floor((host.times.rttvar * 1000000) + 0.5)
    end
    if host.times.timeout ~= nil then
      observation.nmap_timeout_us = math_floor((host.times.timeout * 1000000) + 0.5)
    end
  end

  return observation
end

local function store_observation(observation)
  REGISTRY_MUTEX("lock")
  local ok, storage_error = pcall(function()
    local state = nmap.registry[REGISTRY_KEY]
    if state == nil then
      state = {observations = {}}
      nmap.registry[REGISTRY_KEY] = state
    elseif state.observations == nil then
      state.observations = {}
    end

    state.observations[#state.observations + 1] = observation
  end)
  REGISTRY_MUTEX("done")

  if not ok then
    error(storage_error)
  end
end

local OBSERVATION_OUTPUT_KEYS = {
  "schema",
  "target",
  "hostname",
  "port",
  "protocol",
  "service",
  "tls",
  "path",
  "method",
  "success",
  "status",
  "error",
  "elapsed_us",
  "total_elapsed_us",
  "attempts",
  "fallback_used",
  "content_length",
  "body_bytes",
  "raw_body_bytes",
  "body_bytes_observed",
  "raw_body_bytes_observed",
  "body_truncated",
  "content_type",
  "server",
  "redirects_followed",
  "nmap_srtt_us",
  "nmap_rttvar_us",
  "nmap_timeout_us",
}

local function observation_output(observation)
  local output = stdnse.output_table()
  for _, key in ipairs(OBSERVATION_OUTPUT_KEYS) do
    if observation[key] ~= nil then
      output[key] = observation[key]
    end
  end
  return output
end

local function collect_http_observation(host, port)
  local config = load_request_config(host)
  local response, elapsed_us = make_request(host, port, config.method, config)
  local selected_method = config.method
  local selected_elapsed_us = elapsed_us
  local total_elapsed_us = elapsed_us
  local attempts = 1
  local fallback_used = false

  if should_fallback_to_get(response, config) then
    local fallback_response, fallback_elapsed_us = make_request(host, port, "GET", config)
    attempts = 2
    fallback_used = true
    total_elapsed_us = total_elapsed_us + fallback_elapsed_us

    -- Retain a successful HEAD result when the fallback itself fails. Otherwise,
    -- use the GET result because it provides an observed body size.
    if fallback_response ~= nil and fallback_response.status ~= nil then
      response = fallback_response
      selected_method = "GET"
      selected_elapsed_us = fallback_elapsed_us
    end
  end

  local request_metadata = {
    method = selected_method,
    elapsed_us = selected_elapsed_us,
    total_elapsed_us = total_elapsed_us,
    attempts = attempts,
    fallback_used = fallback_used,
  }
  local observation = build_observation(host, port, response, request_metadata, config)
  store_observation(observation)
  return observation_output(observation)
end

local function leading_digit(value)
  if value == nil or value <= 0 then
    return nil
  end

  local normalized = value
  while normalized < 1 do
    normalized = normalized * 10
  end
  while normalized >= 10 do
    normalized = normalized / 10
  end

  local digit = math_floor(normalized)
  if digit >= 1 and digit <= 9 then
    return digit
  end
  return nil
end

local function feature_values(observations, feature)
  local values = {}
  for _, observation in ipairs(observations) do
    local value = observation[feature]
    local include = value ~= nil and value > 0

    if feature == "elapsed_us" or feature == "total_elapsed_us" or feature == "content_length" or feature == "body_bytes" or feature == "raw_body_bytes" then
      include = include and observation.success == 1
    end
    if feature == "body_bytes" or feature == "raw_body_bytes" then
      include = include and observation.body_truncated ~= 1
    end

    if include then
      values[#values + 1] = value
    end
  end
  return values
end

local function js_divergence(observed)
  local divergence = 0
  local log_2 = math_log(2)

  for digit = 1, 9 do
    local actual = observed[digit]
    local expected = BENFORD[digit]
    local midpoint = (actual + expected) / 2

    if actual > 0 then
      divergence = divergence + (0.5 * actual * (math_log(actual / midpoint) / log_2))
    end
    divergence = divergence + (0.5 * expected * (math_log(expected / midpoint) / log_2))
  end

  return divergence
end

local function analyze_feature(observations, feature, label, config)
  local values = feature_values(observations, feature)
  local sample_count = #values
  local output = stdnse.output_table()
  output.feature = feature
  output.label = label
  output.observations = #observations
  output.samples = sample_count
  output.excluded = #observations - sample_count

  if sample_count == 0 then
    output.eligible = 0
    output.reasons = {"no positive complete observations"}
    return output
  end

  local minimum = values[1]
  local maximum = values[1]
  local value_counts = {}
  local unique_values = 0
  local dominant_value = values[1]
  local dominant_count = 0
  local digit_counts = {0, 0, 0, 0, 0, 0, 0, 0, 0}

  for _, value in ipairs(values) do
    if value < minimum then
      minimum = value
    end
    if value > maximum then
      maximum = value
    end

    local key = tostring(value)
    if value_counts[key] == nil then
      value_counts[key] = {value = value, count = 0}
      unique_values = unique_values + 1
    end
    value_counts[key].count = value_counts[key].count + 1
    if value_counts[key].count > dominant_count then
      dominant_count = value_counts[key].count
      dominant_value = value
    end

    local digit = leading_digit(value)
    if digit ~= nil then
      digit_counts[digit] = digit_counts[digit] + 1
    end
  end

  local orders = maximum > minimum and (math_log(maximum / minimum) / LOG_10) or 0
  local unique_ratio = unique_values / sample_count
  local duplicate_ratio = 1 - unique_ratio
  local dominant_share = dominant_count / sample_count

  output.minimum = minimum
  output.maximum = maximum
  output.orders_of_magnitude = round(orders, 4)
  output.unique_values = unique_values
  output.unique_ratio = round(unique_ratio, 4)
  output.duplicate_ratio = round(duplicate_ratio, 4)
  output.dominant_value = dominant_value
  output.dominant_share = round(dominant_share, 4)

  local reasons = {}
  local minimum_for_expected_counts = math.ceil(5 / BENFORD[9])
  local required_samples = math.max(config.min_samples, minimum_for_expected_counts)
  if sample_count < required_samples then
    reasons[#reasons + 1] = string_format("sample count %d is below required %d", sample_count, required_samples)
  end
  if orders < config.min_orders then
    reasons[#reasons + 1] = string_format("numeric span %.3f orders is below required %.3f", orders, config.min_orders)
  end
  if unique_values < config.min_unique_values then
    reasons[#reasons + 1] = string_format("unique value count %d is below required %d", unique_values, config.min_unique_values)
  end
  if unique_ratio < config.min_unique_ratio then
    reasons[#reasons + 1] = string_format("unique ratio %.3f is below required %.3f", unique_ratio, config.min_unique_ratio)
  end

  if #reasons > 0 then
    output.eligible = 0
    output.reasons = reasons
    return output
  end

  output.eligible = 1
  local observed = {}
  local mad = 0
  local chi_square = 0
  local largest_digit = 1
  local largest_delta = 0
  local digit_rows = {}

  for digit = 1, 9 do
    observed[digit] = digit_counts[digit] / sample_count
    local delta = observed[digit] - BENFORD[digit]
    mad = mad + math_abs(delta)
    local expected_count = sample_count * BENFORD[digit]
    chi_square = chi_square + (((digit_counts[digit] - expected_count) ^ 2) / expected_count)

    if math_abs(delta) > math_abs(largest_delta) then
      largest_digit = digit
      largest_delta = delta
    end

    if config.show_digits then
      local row = stdnse.output_table()
      row.digit = digit
      row.count = digit_counts[digit]
      row.observed = round(observed[digit], 6)
      row.expected = round(BENFORD[digit], 6)
      row.delta_percentage_points = round(delta * 100, 4)
      digit_rows[#digit_rows + 1] = row
    end
  end

  output.mad = round(mad / 9, 8)
  output.js_divergence = round(js_divergence(observed), 8)
  output.chi_square = round(chi_square, 4)
  output.chi_square_degrees_of_freedom = 8
  output.largest_deviation_digit = largest_digit
  output.largest_deviation_percentage_points = round(largest_delta * 100, 4)
  if config.show_digits then
    output.digits = digit_rows
  end

  return output
end

local function summarize_scan()
  local state = nmap.registry[REGISTRY_KEY]
  if state == nil or state.observations == nil or #state.observations == 0 then
    return nil
  end

  local config = load_summary_config()
  local observations = state.observations
  local successful = 0
  for _, observation in ipairs(observations) do
    if observation.success == 1 then
      successful = successful + 1
    end
  end

  local output = stdnse.output_table()
  output.schema = "benmap.http.summary.v1"
  output.observations = #observations
  output.successful = successful
  output.failed = #observations - successful
  output.policy = stdnse.output_table()
  output.policy.min_samples = config.min_samples
  output.policy.min_orders_of_magnitude = config.min_orders
  output.policy.min_unique_values = config.min_unique_values
  output.policy.min_unique_ratio = config.min_unique_ratio
  output.features = {
    analyze_feature(observations, "elapsed_us", "HTTP request elapsed time (microseconds)", config),
    analyze_feature(observations, "content_length", "Declared HTTP content length (bytes)", config),
    analyze_feature(observations, "body_bytes", "Complete decoded HTTP body size (bytes)", config),
    analyze_feature(observations, "nmap_srtt_us", "Nmap smoothed host RTT (microseconds; experimental)", config),
  }
  output.interpretation = "Distribution diagnostic only; deviation is not evidence of compromise."

  return output
end

local ACTIONS = {
  portrule = collect_http_observation,
  postrule = summarize_scan,
}

action = function(...)
  return ACTIONS[SCRIPT_TYPE](...)
end
