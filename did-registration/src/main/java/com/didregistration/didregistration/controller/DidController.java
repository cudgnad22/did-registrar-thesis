package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.repository.DidRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/** Trang web liệt kê các DID do ứng dụng quản lý. */
@Controller
public class DidController {

    private final DidRepository didRepository;

    public DidController(DidRepository didRepository) {
        this.didRepository = didRepository;
    }

    @GetMapping({"/", "/dids"})
    public String listDids(Model model) {
        model.addAttribute("dids", didRepository.findAll());
        return "index";
    }
}
