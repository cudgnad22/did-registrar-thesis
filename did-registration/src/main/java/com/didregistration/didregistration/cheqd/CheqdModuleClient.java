package com.didregistration.didregistration.cheqd;

import com.didregistration.didregistration.cheqd.dto.*;
import com.didregistration.didregistration.dto.api.ApiErrorResponse;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Duration;
import java.util.List;

/**
 * Client gọi module did:cheqd nội bộ .
 * Lớp này không giữ khóa nào: chỉ chuyển dữ liệu cần ký và chữ ký giữa phần điều phối và module.
 */
@Component
public class CheqdModuleClient {

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;

    public CheqdModuleClient(WebClient cheqdModuleWebClient,
                             ObjectMapper objectMapper,
                             @Value("${cheqd.module.timeout-seconds:60}") long timeoutSeconds) {
        this.webClient = cheqdModuleWebClient;
        this.objectMapper = objectMapper;
        // submit phải chờ giao dịch vào block (khoảng 3 giây trên localnet) nên để timeout rộng
        this.timeout = Duration.ofSeconds(timeoutSeconds);
    }

    /** Bước 1: lấy dữ liệu cần ký và danh sách khóa phải ký. */
    public PrepareResponse prepare(String operation, String did, JsonNode didDocument) {
        return post("/internal/cheqd/prepare", new PrepareRequest(operation, did, didDocument), PrepareResponse.class);
    }


    /** Bước 2: gửi chữ ký của Client; module kiểm tra chữ ký rồi gửi giao dịch lên mạng. */
    public SubmitResponse submit(String operation, String did, JsonNode didDocument,
                                 String versionId, List<SignatureItem> signatures) {
        return post("/internal/cheqd/submit",
                new SubmitRequest(operation, did, didDocument, versionId, signatures), SubmitResponse.class);
    }

    /** Đọc DID Document hiện hành từ mạng cheqd. */
    public JsonNode resolve(String did) {
        try {
            return webClient.get()
                    .uri("/internal/cheqd/dids/{did}", did)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block(timeout);
        } catch (RuntimeException e) {
            throw translate(e);
        }
    }

    private <T> T post(String path, Object body, Class<T> responseType) {
        try {
            return webClient.post()
                    .uri(path)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(responseType)
                    .block(timeout);
        } catch (RuntimeException e) {
            throw translate(e);
        }
    }

    /** Chuyển các loại lỗi của WebClient thành CheqdModuleException có mã rõ ràng. */
    private RuntimeException translate(RuntimeException e) {
        if (e instanceof WebClientResponseException r) {
            // Module trả lỗi có cấu trúc {"error":{code,message}}
            try {
                ApiErrorResponse err = objectMapper.readValue(r.getResponseBodyAsString(), ApiErrorResponse.class);
                return new CheqdModuleException(r.getStatusCode().value(), err.error().code(), err.error().message());
            } catch (Exception parseError) {
                return new CheqdModuleException(r.getStatusCode().value(), "UNKNOWN", r.getResponseBodyAsString());
            }
        }
        if (e instanceof WebClientRequestException) {
            // Không kết nối được tới module (container dừng, sai URL...)
            return new CheqdModuleException(503, "MODULE_UNAVAILABLE", e.getMessage());
        }
        if (e instanceof IllegalStateException && String.valueOf(e.getMessage()).contains("Timeout")) {
            return new CheqdModuleException(504, "MODULE_TIMEOUT", e.getMessage());
        }
        return e;
    }
}
