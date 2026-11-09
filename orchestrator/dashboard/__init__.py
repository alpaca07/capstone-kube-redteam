"""공수 공진화 관제 대시보드(포트 12345) — VM C 서빙, 기존 :8090 과 별개의 신규 대시보드.

좌측 세로 내비 + 보안 태세 개요(홈)·실험 제어·실시간 관측·공수 통계·이벤트 로그를 기존 로그
(rounds/episodes.jsonl · progress.json · runs.jsonl · events.jsonl · round_detail · defense_topology)
로 그린다. 공격·방어 노드 그래프·보고서는 다음 단계.

실행:  PORT=12345 python3 -m orchestrator.dashboard
"""
