package com.github.lisama569.threatinteliocservicejava.api;

import com.github.lisama569.threatinteliocservicejava.model.RawIocReport;
import com.github.lisama569.threatinteliocservicejava.service.HitResult;
import com.github.lisama569.threatinteliocservicejava.service.IngestResult;
import com.github.lisama569.threatinteliocservicejava.service.IocService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** IOC 接入与命中查询 REST 接口。 */
@RestController
@RequestMapping("/api/iocs")
public class IocController {

    private final IocService service;

    public IocController(IocService service) {
        this.service = service;
    }

    @PostMapping
    public IngestResult ingest(@RequestBody RawIocReport report) {
        return service.ingest(report);
    }

    @GetMapping("/hit")
    public HitResult hit(@RequestParam String type, @RequestParam String value) {
        return service.hit(type, value);
    }

    @DeleteMapping
    public boolean delete(@RequestParam String type, @RequestParam String value) {
        return service.delete(type, value);
    }
}
