# docs/deploy — 자동 기동 설정 (대시보드 제외)

호스트 로그인만 하면 나머지가 알아서 뜨게 하는 조각들. **대시보드는 별도(나중)** —
여기까지는 "사람이 호스트 로그인 → 에이전트·VM·하네스 자동 ↑ → VM C에서 실험 시작".

```
호스트 로그인 (사람이 하는 유일한 것)
 ├─ 스냅샷 에이전트 자동 ↑            [host-startup.bat → 시작프로그램 폴더]
 └─ (선택) VM A/B/C 자동 전원 ↑       [host-startup.bat 의 vmrun start]
      ├─ VM A: 공격 하네스 자동 ↑      [attack-harness.service]
      ├─ VM B: k3s(이미 자동) + 방어 하네스 자동 ↑  [defense-harness.service]
      └─ VM C: (대시보드 웹서버 — 나중)
```

## ⚠ 핵심 제약 — 에이전트는 반드시 '로그인된 데스크톱 세션'
`vmrun`의 VM 재개(start)는 세션0(서비스)에서 안 된다. 그래서:
- 스냅샷 에이전트와 VM 기동은 **Windows 서비스로 등록 금지.**
- **"로그온 시 실행"**(시작프로그램 폴더 또는 작업 스케줄러 "사용자가 로그온한 경우에만")만 사용.
- 호스트는 실험 내내 **로그인 상태 유지**(잠금은 OK, 로그아웃은 에이전트 죽음).

## 파일
- `host-startup.bat` — 호스트(Windows) 로그온 시 실행. VM 전원(선택) + 스냅샷 에이전트.
  `<USER>` 등 경로를 환경에 맞게 치환 후, 이 파일의 **바로가기를 `shell:startup`** 폴더에 넣는다.
- `attack-harness.service` — VM A systemd 유닛(공격 하네스 부팅 자동 기동).
- `defense-harness.service` — VM B systemd 유닛(방어 하네스 부팅 자동 기동).

## systemd 설치 (VM A·B 각각)
```bash
sudo cp <this-file>.service /etc/systemd/system/<name>.service   # 또는 tee 로 작성
sudo systemctl daemon-reload
sudo systemctl enable --now <name>          # 부팅 자동 + 지금 바로 시작
sudo systemctl status <name>                # 확인
journalctl -u <name> -f                     # 로그
```
`User`/`WorkingDirectory` 를 각 VM 사용자에 맞게 치환. 하네스가 kubectl 을 못 찾으면
유닛에 `Environment=PATH=/usr/local/bin:/usr/bin:/bin` 추가.

## 스냅샷/베이스라인과의 관계
systemd 는 **부팅·크래시 복구용**(VM 켜지면 하네스 자동 ↑). 실험 루프 중에는 베이스라인
스냅샷이 "하네스가 떠 있는 상태"를 담고, revert 가 그걸 복원하므로 매 라운드 재기동은 없다.
코드 변경 후 재베이스라인 때만 `sudo systemctl restart defense-harness` → 로그 truncate →
`scripts/baseline.py`.
