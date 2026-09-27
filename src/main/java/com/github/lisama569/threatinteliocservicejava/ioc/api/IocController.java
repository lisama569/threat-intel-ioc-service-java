package com.github.lisama569.threatinteliocservicejava.ioc.api;

import com.github.lisama569.threatinteliocservicejava.ioc.model.HitResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IngestResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IocReport;
import com.github.lisama569.threatinteliocservicejava.ioc.service.IocService;
import org.springframework.web.bind.annotation.*;

/** IOC REST 接口。 */
@RestController
@RequestMapping("/api/ioc")
public class IocController {

    private final IocService iocService;

    public IocController(IocService iocService) {
        this.iocService = iocService;
    }

    @PostMapping("/ingest")
    public IngestResult ingest(@RequestBody IocReport report) {
        return iocService.ingest(report);
    }

    @GetMapping("/lookup")
    public HitResult lookup(@RequestParam String type, @RequestParam String value) {
        return iocService.lookup(type, value);
    }

    @DeleteMapping
    public boolean delete(@RequestParam String type, @RequestParam String value) {
        return iocService.delete(type, value);
    }
}
