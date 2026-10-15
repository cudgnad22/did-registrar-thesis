package com.didregistration.didregistration.dto.dif;

import java.util.List;
import java.util.Map;

/**
 * Request body chung cho create / update / deactivate theo đặc tả DIF DID Registration.
 *
 *   jobId                : null ở lần gọi đầu; có giá trị khi tiếp tục một thao tác (gửi chữ ký)
 *   method               : DID Method (chỉ dùng với create; có thể truyền qua query ?method=cheqd)
 *   did                  : DID đích (bắt buộc với update/deactivate, tùy chọn với create)
 *   options              : clientSecretMode, network, label (label là tùy chọn riêng của ứng dụng)
 *   secret               : chứa signingResponse ở lần gọi thứ hai (Client-managed Secret Mode)
 *   didDocumentOperation : update, mặc định ["setDidDocument"]
 *   didDocument          : create -> một object; update -> mảng object
 */
public record DifRequest(
        String jobId,
        String method,
        String did,
        Map<String, Object> options,
        Map<String, Object> secret,
        List<String> didDocumentOperation,
        Object didDocument
) {
}
