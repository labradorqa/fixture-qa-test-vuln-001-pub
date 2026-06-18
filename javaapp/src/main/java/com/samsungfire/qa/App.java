// javaapp/src/main/java/com/samsungfire/qa/App.java
// 취약 Maven 컴포넌트를 실제 메서드에서 호출 → component→file→function 매칭 + SAST.
package com.samsungfire.qa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.text.StringSubstitutor;
import org.yaml.snakeyaml.Yaml;
import java.io.IOException;

public class App {
    private static final Logger log = LogManager.getLogger(App.class);
    private static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"; // CWE-798

    // CVE-2021-44228 Log4Shell — 신뢰 불가 입력을 그대로 로깅
    public void handleLogin(String username) {
        log.info("login attempt: " + username);
    }

    // CVE-2022-1471 SnakeYAML — 역직렬화로 RCE
    public Object loadYaml(String raw) {
        return new Yaml().load(raw);
    }

    // Jackson polymorphic deserialization (CWE-502)
    public Object deserialize(String json) throws IOException {
        ObjectMapper m = new ObjectMapper();
        m.enableDefaultTyping();
        return m.readValue(json, Object.class);
    }

    // CVE-2022-42889 Text4Shell — commons-text 보간을 사용자 입력에 적용
    public String interpolate(String input) {
        return new StringSubstitutor().replace(input);
    }

    // CWE-78: OS command injection
    public Process runCommand(String cmd) throws IOException {
        return Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
    }
}
