# 하네스 서버 systemd 등록

공격자(VM A)·방어자(VM B) 하네스를 터미널에서 수동으로 띄우는 대신 systemd 서비스로
등록한다 → 부팅 시 자동 기동 + 크래시 시 자동 재시작. 오케스트레이터(VM C)가 매 턴
HTTP 로 호출하는 상주 서비스라 실험 한 판 내내 떠 있어야 한다.

전제: 각 VM 의 `~/capstone` 에 레포와 `config.yaml` 이 있고, `python3 -m attacker.server`
/ `defender.server` 가 그 VM 에서 이미 수동으로 떠 봤다(의존성·config 검증 끝).

## VM A (공격자)

```
sudo cp ~/capstone/deploy/systemd/attacker-harness.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attacker-harness
```

상태·로그:

```
systemctl status attacker-harness
journalctl -u attacker-harness -f
```

## VM B (방어자)

```
sudo cp ~/capstone/deploy/systemd/defender-harness.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now defender-harness
```

```
systemctl status defender-harness
journalctl -u defender-harness -f
```

## 운영 메모

- `config.yaml` 을 고치면 반영하려면 재시작:
  `sudo systemctl restart attacker-harness` (VM A) / `defender-harness` (VM B)
- `git pull` 로 코드 갱신 후에도 재시작해야 반영된다.
- 공격자 서버는 `config.yaml` 의 `attack.exec_mode: true` 로 떠야 발판 파드 안에서 공격이
  돈다(끄면 외부 endpoint 로 붙어 내부 킬체인 미도달 → 크라운 0).
- DGX·모델망이 꺼져 있으면 서버는 떠 있어도 공격/방어 호출이 실패한다(서버 자체는 안 죽음).
  실험 전 모델망만 열어두면 된다.
- 유닛 파일의 `User=`·`WorkingDirectory=` 는 VM A=vm-a, VM B=vm-b, 홈=`/home/<user>/capstone`
  기준. 사용자명·경로가 다르면 그 값으로 바꾼다. `python3` 경로가 `/usr/bin/python3` 가
  아니면(`which python3` 로 확인) `ExecStart=` 도 맞춘다.
- 중지/비활성화: `sudo systemctl disable --now attacker-harness`
- 빠른 생존 확인(VM C 에서): `curl -sS -X POST http://<VM A IP>:8000/status`
