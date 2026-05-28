"""KISA(한국인터넷진흥원) 보안공지 수집 에이전트.

Trivy DB가 다루지 않는 한국 한정 advisory를 수집해 tb_vendor_advisory에 적재.
국내 벤더(한컴/티맥스/안랩 등) 영향 정보 보강.

RSS feed를 일 1회 폴링. 각 공지에서 CVE-XXXX-NNNN 정규식으로 관련 CVE 추출.
"""
