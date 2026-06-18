// src/main/java/com/samsungfire/qa/VulnController.java
// Spring 컨트롤러 — @RequestParam(원격 소스)을 취약 sink로 연결. autobuild로 의존성 해석 시 CodeQL이 탐지.
package com.samsungfire.qa;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

@RestController
public class VulnController {
    private static final Logger log = LogManager.getLogger(VulnController.class);
    private static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"; // CWE-798

    // CWE-78: OS command injection
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c1 " + host});
        return "started:" + p.hashCode();
    }

    // CWE-117 / Log4Shell 표면: 신뢰 불가 입력 로깅
    @GetMapping("/login")
    public String login(@RequestParam String user) {
        log.info("login attempt: " + user);
        return "ok";
    }

    // CWE-89: SQL injection
    @GetMapping("/user")
    public String user(@RequestParam String id) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:mysql://127.0.0.1/app", "root", "rootpass");
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
        return "queried";
    }

    // CWE-502: SnakeYAML 역직렬화
    @GetMapping("/yaml")
    public Object yaml(@RequestParam String raw) {
        return new Yaml().load(raw);
    }

    // CWE-502: Jackson default typing 역직렬화
    @GetMapping("/json")
    public Object json(@RequestParam String body) throws IOException {
        ObjectMapper m = new ObjectMapper();
        m.enableDefaultTyping();
        return m.readValue(body, Object.class);
    }
}
