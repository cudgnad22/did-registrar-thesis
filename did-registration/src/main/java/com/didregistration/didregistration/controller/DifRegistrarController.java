package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.dto.dif.DifRequest;
import com.didregistration.didregistration.dto.dif.DifResponse;
import com.didregistration.didregistration.dto.dif.DifResult;
import com.didregistration.didregistration.service.DidRegistrarService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * HTTPS binding theo đặc tả DIF DID Registration.
 *
 *   POST /1.0/create?method=cheqd
 *   POST /1.0/update
 *   POST /1.0/deactivate
 *
 * Mỗi thao tác gọi hai lần cùng endpoint: lần đầu nhận signingRequest + jobId,
 * lần sau gửi jobId + secret.signingResponse.
 */
@RestController
@RequestMapping("/1.0")
public class DifRegistrarController {

    private final DidRegistrarService registrar;

    public DifRegistrarController(DidRegistrarService registrar) {
        this.registrar = registrar;
    }

    @PostMapping("/create")
    public ResponseEntity<DifResponse> create(@RequestParam(value = "method", required = false) String method,
                                              @RequestBody DifRequest request) {
        return toResponse(registrar.create(method, request));
    }

    @PostMapping("/update")
    public ResponseEntity<DifResponse> update(@RequestBody DifRequest request) {
        return toResponse(registrar.update(request));
    }

    @PostMapping("/deactivate")
    public ResponseEntity<DifResponse> deactivate(@RequestBody DifRequest request) {
        return toResponse(registrar.deactivate(request));
    }

    private ResponseEntity<DifResponse> toResponse(DifResult result) {
        return ResponseEntity.status(result.httpStatus()).body(result.body());
    }
}
