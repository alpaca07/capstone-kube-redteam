@echo off
REM ── 호스트(Windows) 로그온 시 자동 실행 ──────────────────────────────────
REM 이 파일의 '바로가기'를 시작프로그램 폴더에 넣는다:  Win+R → shell:startup
REM ⚠ 반드시 로그인된 데스크톱 세션에서 실행돼야 vmrun 재개가 동작한다(서비스 금지).
REM <USER> 와 경로를 환경에 맞게 치환할 것.

set VMRUN="C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
set REPO=C:\Users\<USER>\Documents\capstone-kube-redteam-main
set VMROOT=C:\Users\<USER>\Documents\Virtual Machines

REM ── (선택) VM 자동 전원 ───────────────────────────────────────────────
REM VM 을 직접 켤 거면 이 3줄 지우기. VM B 는 반드시 gui (스냅샷 재개 때문).
REM A/C 는 리소스 아끼려면 gui 대신 nogui 가능(네트워크로만 접근하니까).
%VMRUN% start "%VMROOT%\VM-C-orchestrator\VM-C-orchestrator.vmx" gui
%VMRUN% start "%VMROOT%\VM-A-attacker\VM-A-attacker.vmx" gui
%VMRUN% start "%VMROOT%\VM-B-target\VM-B-target.vmx" gui

REM ── 스냅샷 에이전트 (이 줄이 창을 점유하며 계속 실행 → 맨 마지막) ──────────
cd /d "%REPO%"
py host\snapshot_agent.py --vmx "%VMROOT%\VM-B-target\VM-B-target.vmx" --vmrun %VMRUN% --host 0.0.0.0 --port 8010
