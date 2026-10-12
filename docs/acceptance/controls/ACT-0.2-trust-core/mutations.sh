#!/usr/bin/env bash
# Проверка того, что Go-контроли C01–C09 и C14 способны краснеть (правило 2).
# Для каждого контроля во ВРЕМЕННОЙ копии репозитория ломается одно место
# кода, которое защищает проверяемое заявление, и контроль должен упасть.
# Код репозитория не меняется. Использование (из корня репозитория):
#   bash docs/acceptance/controls/ACT-0.2-trust-core/mutations.sh
# Код выхода 0 — все мутации «убиты» (контроли покраснели как надо).
# Переменная LOGDIR (необязательная): полный вывод `go test` каждой мутации и её
# описание (файл, было → стало) сохраняются отдельным файлом mutation-<имя>.log.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
CTRL="$REPO/docs/acceptance/controls/ACT-0.2-trust-core"
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# mutate NAME TEST FILE OLD NEW [FILE OLD NEW ...]
mutate() {
  local name="$1" test="$2"; shift 2
  local orig=("$@")
  local d="$W/$name"; mkdir -p "$d"
  (cd "$REPO" && git archive HEAD) | tar -x -C "$d"
  mkdir -p "$d/acceptance"
  for f in "$CTRL"/*_test.go.txt; do cp "$f" "$d/acceptance/$(basename "$f" .txt)"; done
  cp -r "$REPO/docs/acceptance/reference" "$d/acceptance/reference"
  while [ "$#" -ge 3 ]; do
    python3 -I - "$d/$1" "$2" "$3" <<'EOF' || { echo "$name: MUTATION NOT APPLIED"; return 2; }
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("pattern count != 1 in %s" % p)
open(p, "w").write(s.replace(old, new))
EOF
    shift 3
  done
  { echo "# мутация $name; контроль $test"; echo "# изменения (файл | было | стало):"; for ((i=1;i<=${#orig[@]};i+=3)); do echo "#   ${orig[i-1]} | ${orig[i]} | ${orig[i+1]}"; done; echo "# коммит исходного дерева: $(cd "$REPO" && git rev-parse HEAD)"; echo "\$ go test ./acceptance/ -run $test -count=1 -v"; } >"$W/$name.log"
  if (cd "$d" && go test ./acceptance/ -run "$test" -count=1 -v >>"$W/$name.log" 2>&1); then
    [ -n "${LOGDIR:-}" ] && { mkdir -p "$LOGDIR"; cp "$W/$name.log" "$LOGDIR/mutation-$name.log"; }
    echo "$name: SURVIVED (контроль $test остался зелёным) — контроль не ловит эту поломку"
    return 1
  fi
  [ -n "${LOGDIR:-}" ] && { mkdir -p "$LOGDIR"; cp "$W/$name.log" "$LOGDIR/mutation-$name.log"; }
  if grep -q 'build failed' "$W/$name.log"; then
    echo "$name: MUTATION INVALID (не компилируется), результат не засчитывается"
    return 1
  fi
  echo "$name: killed ($test покраснел: $(grep -v '^#' "$W/$name.log" | grep -m1 -E 'FAIL:|expected|NOT|accepted|OK' | cut -c1-110))"
}

rc=0
mutate M1 TestC01 verify/verify.go 'rep.Problems = append(rep.Problems, "entries on disk do not match the signed checkpoint root (log was modified)")' '_ = leaves' || rc=1
mutate M2 TestC02 verify/verify.go 'tlog.OpenCheckpoint(msg, opts.Origin, opts.LogKey)' 'tlog.OpenCheckpoint(msg, "", opts.LogKey)' || rc=1
mutate M3 TestC03 attest/dsse.go 'if !seen[v.KeyID()] && v.Verify(pae, sig) {' 'if !seen[v.KeyID()] && (v.Verify(pae, sig) || true) {' || rc=1
mutate M4 TestC04 verify/chain.go 'if k.log, err = keys.LoadPublic(e.PublicKey); err != nil {' 'if k.log, err = keys.LoadPublic(func() string { if _, e2 := os.Stat(filepath.Join(e.Log, "log.pub")); e2 == nil { return filepath.Join(e.Log, "log.pub") }; return e.PublicKey }()); err != nil {' || rc=1
mutate M5 TestC05 verify/verify.go 'case tlog.RootFromLeaves(leaves[:prev.Size]) != prev.Root:' 'case false:' || rc=1
mutate M6 TestC06 verify/chain.go 'bad("planned rotation without a valid signature by the epoch %d key", prev.Epoch)' '_ = prev' || rc=1
mutate M7 TestC07 verify/chain.go 'bad("unplanned rotation to key %s is not accepted by the manifest (acceptUnplanned)", g.NewKeyID)' '_ = 0' \
  verify/chain.go 'bad("unplanned rotation to key %s, but the manifest accepts %s", g.NewKeyID, cur.AcceptUnplanned)' '_ = 0' || rc=1
mutate M8 TestC08 verify/chain.go 'note("current checkpoint (size %d) is behind' 'bad("current checkpoint (size %d) is behind' || rc=1
mutate M9 TestC09 verify/chain.go 'bad("%d entries after the freeze point of a planned rotation (old key misuse)", er.Unconfirmed)' '_ = er' || rc=1
mutate M10 TestC14a attest/dsse.go 'b.WriteString("DSSEv1 ")' 'b.WriteString("DSSEv0 ")' || rc=1
mutate M11 TestC14e tlog/merkle.go 'h.Write([]byte{0x01})' 'h.Write([]byte{0x02})' || rc=1
mutate M12 TestC14c tlog/checkpoint.go 'h.Write([]byte("\n"))' 'h.Write([]byte("\r"))' || rc=1
mutate M13 TestC14f tlog/merkle.go 'return append(path(m, leaves[:k]), mth(leaves[k:]))' 'return append(path(m, leaves[:k]), mth(leaves[:k]))' || rc=1
mutate M14 TestC14g attest/statement.go 'StatementType = "https://in-toto.io/Statement/v1"' 'StatementType = "https://in-toto.io/Statement/v0.1"' || rc=1
mutate M15 TestC14d tlog/checkpoint.go '"%s\n%d\n%s\n"' '"%s\n%d\n%s"' || rc=1
exit $rc
