# pyapp/config.py — insecure config loading for IVAS SAST QA.
# 취약 컴포넌트(PyYAML)를 실제 함수에서 호출 → component→file→function 매칭.
import yaml  # PyYAML 3.13 (CVE-2017-18342)

API_TOKEN = "ghp_FAKE000000000000000000000000000000"  # 하드코딩 시크릿 (CWE-798)
DB_PASSWORD = "rootpass"


def load_config(raw):
    # CWE-502: 신뢰 불가 입력을 yaml.load → 임의 코드 실행
    return yaml.load(raw)


def eval_setting(expr):
    # CWE-95: eval 인젝션
    return eval(expr)
