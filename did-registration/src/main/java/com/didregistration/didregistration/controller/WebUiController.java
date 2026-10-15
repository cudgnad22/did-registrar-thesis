package com.didregistration.didregistration.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Điều hướng tới các trang giao diện tĩnh (src/main/resources/static):
 *   /ui/create, /ui/update, /ui/deactivate, /ui/dids
 *              giao diện trực quan (một tệp ui/index.html, chọn thao tác theo đường dẫn)
 *   /api-docs  tài liệu API dạng Swagger UI, đọc đặc tả từ /api-docs/openapi.json
 */
@Controller
public class WebUiController {

    @GetMapping({"/ui", "/ui/"})
    public String registrarUi() {
        return "redirect:/ui/create";
    }

    @GetMapping({"/ui/create", "/ui/update", "/ui/deactivate", "/ui/dids"})
    public String registrarUiPage() {
        // Giữ nguyên địa chỉ trên trình duyệt; trang tự chọn thao tác theo location.pathname
        return "forward:/ui/index.html";
    }

    @GetMapping({"/api-docs", "/api-docs/"})
    public String apiDocs() {
        return "redirect:/api-docs/index.html";
    }
}
