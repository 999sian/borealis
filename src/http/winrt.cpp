#include "../ascii.hpp"
#include "../http_internal.hpp"

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.Web.Http.Filters.h>
#include <winrt/Windows.Web.Http.Headers.h>
#include <winrt/Windows.Web.Http.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>

namespace borealis::http {
namespace {
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Storage::Streams;
using namespace winrt::Windows::Web::Http;
using namespace winrt::Windows::Web::Http::Filters;

struct Apartment {
    Apartment() { winrt::init_apartment(winrt::apartment_type::multi_threaded); }
    ~Apartment() {
        winrt::clear_factory_cache();
        winrt::uninit_apartment();
    }
};
}  // namespace

bool available() noexcept {
    return true;
}
Backend backend() noexcept {
    return Backend::WinRt;
}
const char* backend_name() noexcept {
    return "Windows.Web.Http";
}

detail::TransportResult detail::send_request(const TransportRequest& request) {
    try {
        // C++/WinRT caches activation factories; keep their apartment alive across requests.
        thread_local Apartment apartment;
        Deadline::Tracker activity;
        auto wait = [&](const auto& operation) {
            struct Completion {
                std::mutex mutex;
                std::condition_variable changed;
                bool done = false;
            };
            auto completion = std::make_shared<Completion>();
            operation.Completed([completion](const auto&, AsyncStatus) {
                std::lock_guard lock{completion->mutex};
                completion->done = true;
                completion->changed.notify_one();
            });
            std::unique_lock lock{completion->mutex};
            while (!completion->done) {
                if (request.signals->cancelRequested.load(std::memory_order_relaxed)) {
                    lock.unlock();
                    operation.Cancel();
                    return Error::Canceled;
                }
                if (request.deadline->expired(activity)) {
                    lock.unlock();
                    operation.Cancel();
                    return Error::Timeout;
                }
                completion->changed.wait_for(lock, Deadline::PollInterval);
            }
            return Error::None;
        };
        auto interrupted = [](Error error) -> TransportResult {
            return {.error = error,
                .message = error == Error::Timeout ? "Request timed out" : "Request canceled"};
        };

        HttpBaseProtocolFilter filter;
        filter.AllowAutoRedirect(false);
        filter.AutomaticDecompression(request.allowCompression);
        filter.CacheControl().ReadBehavior(HttpCacheReadBehavior::NoCache);
        filter.CacheControl().WriteBehavior(HttpCacheWriteBehavior::NoCache);
        HttpClient client{filter};
        Uri uri{winrt::to_hstring(request.url)};
        auto method = request.method;
        auto headers = request.headers;

        for (unsigned redirects = 0; redirects <= 10; ++redirects) {
            if (request.signals->cancelRequested.load(std::memory_order_relaxed)) {
                return interrupted(Error::Canceled);
            }
            if (request.deadline->expired(activity)) {
                return interrupted(Error::Timeout);
            }
            if (uri.SchemeName() != L"https") {
                return {.error = Error::UnsupportedScheme,
                    .message = "Only HTTPS redirects are supported"};
            }
            HttpRequestMessage message{HttpMethod{winrt::to_hstring(method_name(method))}, uri};
            if (method_has_request_body(method)) {
                if (request.body.size() > std::numeric_limits<uint32_t>::max()) {
                    return {.error = Error::TooLarge, .message = "Request body is too large"};
                }
                Buffer body{static_cast<uint32_t>(request.body.size())};
                body.Length(static_cast<uint32_t>(request.body.size()));
                if (!request.body.empty()) {
                    std::memcpy(body.data(), request.body.data(), request.body.size());
                }
                message.Content(HttpBufferContent{body});
            }
            for (const auto& header : headers) {
                const auto name = winrt::to_hstring(header.name);
                const auto value = winrt::to_hstring(header.value);
                if (!message.Headers().TryAppendWithoutValidation(name, value)) {
                    if (!message.Content() ||
                        !message.Content().Headers().TryAppendWithoutValidation(name, value))
                    {
                        return {.error = Error::Network, .message = "Invalid request header"};
                    }
                }
            }
            activity.reset();
            auto sending =
                client.SendRequestAsync(message, HttpCompletionOption::ResponseHeadersRead);
            if (const auto error = wait(sending); error != Error::None) {
                return interrupted(error);
            }
            auto response = sending.get();
            const auto status = static_cast<int>(response.StatusCode());
            if ((status == 301 || status == 302 || status == 303 || status == 307 ||
                    status == 308) &&
                response.Headers().HasKey(L"Location"))
            {
                if (redirects == 10) {
                    return {.error = Error::Network, .message = "Too many redirects"};
                }
                auto next = uri.CombineUri(response.Headers().Lookup(L"Location"));
                if (next.Host() != uri.Host() || next.Port() != uri.Port()) {
                    std::erase_if(headers, [](const Header& h) {
                        return borealis::detail::ascii_iequals(h.name, "Authorization") ||
                               borealis::detail::ascii_iequals(h.name, "Cookie");
                    });
                }
                if ((status == 303 && method != Method::Head) ||
                    ((status == 301 || status == 302) && method == Method::Post))
                {
                    method = Method::Get;
                    std::erase_if(headers, [](const Header& h) {
                        return borealis::detail::ascii_iequals(h.name, "Content-Type") ||
                               borealis::detail::ascii_iequals(h.name, "Content-Length");
                    });
                }
                uri = next;
                continue;
            }
            activity.start_response();
            std::vector<Header> responseHeaders;
            for (const auto& h : response.Headers()) {
                responseHeaders.push_back({winrt::to_string(h.Key()), winrt::to_string(h.Value())});
            }
            if (response.Content()) {
                for (const auto& h : response.Content().Headers()) {
                    responseHeaders.push_back(
                        {winrt::to_string(h.Key()), winrt::to_string(h.Value())});
                }
            }
            if (request.observer->on_response(status, std::move(responseHeaders)) ==
                    TransportObserver::Directive::Abort ||
                method == Method::Head || !response.Content())
            {
                return {};
            }
            auto opening = response.Content().ReadAsInputStreamAsync();
            if (const auto error = wait(opening); error != Error::None) {
                return interrupted(error);
            }
            auto stream = opening.get();
            IBuffer buffer = Buffer{64 * 1024};
            for (;;) {
                auto reading =
                    stream.ReadAsync(buffer, buffer.Capacity(), InputStreamOptions::Partial);
                if (const auto error = wait(reading); error != Error::None) {
                    return interrupted(error);
                }
                buffer = reading.get();
                if (buffer.Length() == 0) {
                    return {};
                }
                activity.touch();
                if (request.observer->on_data({reinterpret_cast<const std::byte*>(buffer.data()),
                        buffer.Length()}) == TransportObserver::Directive::Abort)
                {
                    return {};
                }
            }
        }
        return {.error = Error::Network, .message = "Too many redirects"};
    } catch (const winrt::hresult_error& error) {
        return {.error = Error::Network, .message = winrt::to_string(error.message())};
    }
}
}  // namespace borealis::http
