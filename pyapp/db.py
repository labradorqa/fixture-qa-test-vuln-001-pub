# pyapp/db.py — SQLi / SSRF / command injection / XXE for IVAS SAST QA.
# 취약 컴포넌트(requests, SQLAlchemy, lxml)를 함수에서 직접 사용.
import subprocess
import requests  # requests 2.19.1 (CVE-2018-18074)
from sqlalchemy import create_engine, text  # SQLAlchemy 1.2.18 (CVE-2019-7164)
from lxml import etree  # lxml 4.6.2 (XXE)

engine = create_engine("mysql://root:rootpass@127.0.0.1:3306/app")


def find_user(user_id):
    # CWE-89: 문자열 포매팅으로 SQL 조립 → SQL injection
    sql = "SELECT * FROM users WHERE id = %s" % user_id
    with engine.connect() as conn:
        return conn.execute(text(sql)).fetchall()


def fetch_url(url):
    # CWE-918: 사용자 제어 URL → SSRF
    return requests.get(url, verify=False).text


def ping(host):
    # CWE-78: shell=True 로 OS command injection
    return subprocess.check_output("ping -c1 " + host, shell=True)


def parse_xml(xml_bytes):
    # CWE-611: 외부 엔티티 허용 → XXE
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(xml_bytes, parser)
